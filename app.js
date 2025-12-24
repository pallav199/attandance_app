const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const xlsx = require('xlsx');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const { openDb, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Railway/Render deployments
app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-attendance',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    if (req.session.user.role !== role) return res.status(403).send('Forbidden');
    next();
  };
}

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const role = req.session.user.role;
  if (role === 'admin') return res.redirect('/admin');
  if (role === 'teacher') return res.redirect('/teacher');
  return res.redirect('/student');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await openDb();
  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (!user) return res.render('login', { error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.render('login', { error: 'Invalid credentials' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  console.log('User logged in:', req.session.user);
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Forgot Password Routes
app.get('/forgot-password', (req, res) => {
  res.render('forgot_password', { error: null, message: null });
});

app.post('/forgot-password', async (req, res) => {
  const { username, newPassword, confirmPassword } = req.body;

  if (!username || !newPassword || !confirmPassword) {
    return res.render('forgot_password', {
      error: 'All fields are required',
      message: null
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render('forgot_password', {
      error: 'Passwords do not match',
      message: null
    });
  }

  if (newPassword.length < 6) {
    return res.render('forgot_password', {
      error: 'Password must be at least 6 characters long',
      message: null
    });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);

    if (!user) {
      return res.render('forgot_password', {
        error: 'Username not found',
        message: null
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE username = ?', hashedPassword, username);

    res.render('forgot_password', {
      error: null,
      message: 'Password reset successfully! You can now login with your new password.'
    });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.render('forgot_password', {
      error: 'An error occurred. Please try again.',
      message: null
    });
  }
});

// Change Password Routes
app.get('/change-password', requireAuth, (req, res) => {
  res.render('change_password', { error: null, message: null, user: req.session.user });
});

app.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.session.user.id;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.render('change_password', {
      error: 'All fields are required',
      message: null,
      user: req.session.user
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render('change_password', {
      error: 'New passwords do not match',
      message: null,
      user: req.session.user
    });
  }

  if (newPassword.length < 6) {
    return res.render('change_password', {
      error: 'Password must be at least 6 characters long',
      message: null,
      user: req.session.user
    });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE id = ?', userId);

    if (!user) {
      return res.render('change_password', {
        error: 'User not found',
        message: null,
        user: req.session.user
      });
    }

    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValidPassword) {
      return res.render('change_password', {
        error: 'Current password is incorrect',
        message: null,
        user: req.session.user
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', hashedPassword, userId);

    res.render('change_password', {
      error: null,
      message: 'Password changed successfully!',
      user: req.session.user
    });
  } catch (error) {
    console.error('Error changing password:', error);
    res.render('change_password', {
      error: 'An error occurred. Please try again.',
      message: null,
      user: req.session.user
    });
  }
});

// Admin routes
// ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const upload = multer({ dest: uploadsDir });

app.get('/admin', requireRole('admin'), async (req, res) => {
  const db = await openDb();
  const students = await db.all('SELECT * FROM students ORDER BY name');
  res.render('admin', { message: null, students });
});

// Upload students Excel
app.post('/admin/upload', requireRole('admin'), upload.single('students'), async (req, res) => {
  console.log('Received upload request');
  if (!req.file) {
    console.log('No file in request');
    return res.render('admin', { message: 'No file uploaded' });
  }
  console.log('Uploaded file:', req.file.originalname, req.file.path);
  let message = 'Upload processed';
  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(sheet, { defval: '' });
    const db = await openDb();
    // Insert with OR IGNORE to avoid duplicates and ensure student_id/name present
    const stmt = await db.prepare('INSERT OR IGNORE INTO students (student_id, name) VALUES (?, ?)');
    try {
      await db.run('BEGIN');
      let inserted = 0;
      for (const r of rows) {
        // detect common id & name keys
        let sid = String(r.student_id || r.id || r.StudentID || r.StudentId || r['Student ID'] || '').trim();
        const name = (r.name || r.Name || r.full_name || r.FullName || r['Full Name'] || r['Student Name'] || '').trim();
        if (sid) sid = sid.toUpperCase();
        if (!sid || !name) continue;
        const info = await stmt.run(sid, name);
        if (info && info.changes) inserted++;
      }
      await db.run('COMMIT');
      message = `Upload processed. ${inserted} new students added.`;
    } catch (e) {
      await db.run('ROLLBACK');
      console.error('DB error while inserting students:', e);
      message = 'Database error while inserting students';
    } finally {
      await stmt.finalize();
    }
  } catch (e) {
    console.error('Error processing uploaded file:', e.message || e);
    message = 'Error processing uploaded file: ' + (e.message || e);
  } finally {
    try { fs.unlinkSync(req.file.path); } catch (e) { /* ignore */ }
  }
  console.log('Upload result:', message);
  // If the uploader is admin, redirect to teacher dashboard so attendance page is visible
  if (req.session.user && req.session.user.role === 'admin') {
    return res.redirect('/teacher');
  }
  try {
    const db = await openDb();
    const students = await db.all('SELECT * FROM students ORDER BY name');
    res.render('admin', { message, students });
  } catch (e) {
    console.error('Could not fetch students after upload', e);
    res.render('admin', { message, students: [] });
  }
});

// Serve a small CSV sample template for admins to test uploads
app.get('/download-sample', requireRole('admin'), (req, res) => {
  const csv = 'student_id,name\nS1001,Test Student 1\nS1002,Test Student 2\n';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="students-sample.csv"');
  res.send(csv);
});

// Delete all students and their attendance records
app.post('/admin/delete-all-students', requireRole('admin'), async (req, res) => {
  console.log('Admin requested to delete all students');
  try {
    const db = await openDb();
    await db.run('BEGIN');

    // Delete all attendance records first (foreign key constraint)
    await db.run('DELETE FROM attendance');
    console.log('Deleted all attendance records');

    // Delete all students
    const result = await db.run('DELETE FROM students');
    console.log('Deleted all students');

    await db.run('COMMIT');

    const deletedCount = result.changes || 0;
    const message = `Successfully deleted all students (${deletedCount} students removed) and their attendance records.`;

    const students = await db.all('SELECT * FROM students ORDER BY name');
    res.render('admin', { message, students });
  } catch (e) {
    console.error('Error deleting students:', e);
    const db = await openDb();
    try {
      await db.run('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Rollback error:', rollbackErr);
    }
    const students = await db.all('SELECT * FROM students ORDER BY name');
    res.render('admin', { message: 'Error deleting students: ' + e.message, students });
  }
});

// Teacher routes
app.get('/teacher', requireAuth, async (req, res) => {
  // allow admin to view the teacher dashboard in read-only mode
  if (req.session.user.role !== 'teacher' && req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  const db = await openDb();

  // Pagination parameters
  const itemsPerPage = 10;
  const currentPage = parseInt(req.query.page) || 1;
  const offset = (currentPage - 1) * itemsPerPage;

  // Get total count of students
  const totalCountRow = await db.get('SELECT COUNT(*) as count FROM students');
  const totalStudents = totalCountRow.count;
  const totalPages = Math.ceil(totalStudents / itemsPerPage);

  // Fetch paginated students
  const students = await db.all('SELECT * FROM students ORDER BY name LIMIT ? OFFSET ?', itemsPerPage, offset);
  const canMark = req.session.user.role === 'teacher';
  // handle selected date (YYYY-MM-DD) to show attendance for that day
  const selectedDate = req.query.date || new Date().toISOString().slice(0, 10);
  // fetch attendance for that date
  const attRows = await db.all('SELECT student_id, status FROM attendance WHERE date = ?', selectedDate);
  const attendanceMap = {};
  for (const a of attRows) attendanceMap[a.student_id] = a.status;

  // build days array for the month of selectedDate
  const [y, m, d] = selectedDate.split('-').map(s => parseInt(s, 10));
  const year = y;
  const month = m; // 1-12
  const first = new Date(year, month - 1, 1);
  const daysInMonth = new Date(year, month, 0).getDate();
  const days = [];
  for (let day = 1; day <= daysInMonth; day++) {
    const mm = String(month).padStart(2, '0');
    const dd = String(day).padStart(2, '0');
    days.push({ date: `${year}-${mm}-${dd}`, day });
  }

  res.render('dashboard', {
    students,
    canMark,
    selectedDate,
    attendanceMap,
    days,
    pagination: {
      currentPage,
      totalPages,
      totalStudents,
      itemsPerPage,
      startIndex: offset + 1,
      endIndex: Math.min(offset + itemsPerPage, totalStudents)
    }
  });
});

app.post('/teacher/mark', requireRole('teacher'), async (req, res) => {
  const { date, statuses } = req.body; // statuses: { studentId: 'present'|'absent' }
  const page = req.query.page || 1; // Preserve the current page
  console.log('Saving attendance for date:', date, 'raw statuses payload:', statuses);
  if (!statuses || Object.keys(statuses).length === 0) {
    console.warn('No statuses received in request body');
    // redirect back with query flag
    return res.redirect(`/teacher?date=${encodeURIComponent(date)}&page=${page}&saved=0`);
  }
  const db = await openDb();
  const stmt = await db.prepare('INSERT OR REPLACE INTO attendance (student_id, date, status) VALUES (?, ?, ?)');
  try {
    await db.run('BEGIN');
    for (const sid in statuses) {
      const status = statuses[sid];
      const key = String(sid).toUpperCase();
      await stmt.run(key, date, status);
    }
    await db.run('COMMIT');
  } catch (e) {
    await db.run('ROLLBACK');
    console.error(e);
  } finally {
    await stmt.finalize();
  }
  // redirect back to the same date and page so teacher sees saved values
  res.redirect(`/teacher?date=${encodeURIComponent(date)}&page=${page}`);
});

// Student dashboard
app.get('/student', requireAuth, async (req, res) => {
  const db = await openDb();
  const user = req.session.user;
  // if student
  if (user.role !== 'student') {
    return res.status(403).send('Forbidden');
  }

  // Pagination parameters
  const itemsPerPage = 10;
  const currentPage = parseInt(req.query.page) || 1;
  const offset = (currentPage - 1) * itemsPerPage;

  // Get total count of students
  const totalCountRow = await db.get('SELECT COUNT(*) as count FROM students');
  const totalStudents = totalCountRow.count;
  const totalPages = Math.ceil(totalStudents / itemsPerPage);

  // Fetch paginated students
  const students = await db.all('SELECT * FROM students ORDER BY name LIMIT ? OFFSET ?', itemsPerPage, offset);

  // handle selected date (YYYY-MM-DD) to show attendance for that day
  const selectedDate = req.query.date || new Date().toISOString().slice(0, 10);
  // fetch attendance for that date
  const attRows = await db.all('SELECT student_id, status FROM attendance WHERE date = ?', selectedDate);
  const attendanceMap = {};
  for (const a of attRows) attendanceMap[a.student_id] = a.status;

  // build days array for the month of selectedDate
  const [y, m, d] = selectedDate.split('-').map(s => parseInt(s, 10));
  const year = y;
  const month = m; // 1-12
  const first = new Date(year, month - 1, 1);
  const daysInMonth = new Date(year, month, 0).getDate();
  const days = [];
  for (let day = 1; day <= daysInMonth; day++) {
    const mm = String(month).padStart(2, '0');
    const dd = String(day).padStart(2, '0');
    days.push({ date: `${year}-${mm}-${dd}`, day });
  }

  res.render('dashboard', {
    students,
    canMark: false,
    selectedDate,
    attendanceMap,
    days,
    pagination: {
      currentPage,
      totalPages,
      totalStudents,
      itemsPerPage,
      startIndex: offset + 1,
      endIndex: Math.min(offset + itemsPerPage, totalStudents)
    }
  });
});

// API endpoint to get monthly attendance summary for a student
app.get('/api/student-monthly-summary', requireAuth, async (req, res) => {
  const { studentId, date } = req.query;
  if (!studentId || !date) {
    return res.status(400).json({ error: 'Missing studentId or date' });
  }

  const db = await openDb();

  // Extract year and month from the date
  const [year, month] = date.split('-');
  const start = `${year}-${month}-01`;
  const end = `${year}-${month}-31`;

  // Get student info
  const student = await db.get('SELECT * FROM students WHERE student_id = ?', studentId);
  if (!student) {
    return res.status(404).json({ error: 'Student not found' });
  }

  // Get attendance summary for the month
  const summary = await db.get(`
    SELECT
      SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as presents,
      SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absents,
      COUNT(*) as total_marked
    FROM attendance
    WHERE student_id = ? AND date BETWEEN ? AND ?
  `, studentId, start, end);

  res.json({
    student: {
      id: student.student_id,
      name: student.name
    },
    month: new Date(date).toLocaleString('default', { month: 'long', year: 'numeric' }),
    summary: {
      present: summary.presents || 0,
      absent: summary.absents || 0,
      totalMarked: summary.total_marked || 0
    }
  });
});

// Summary for teacher and student
app.get('/summary', requireAuth, async (req, res) => {
  const db = await openDb();
  const { month, year } = req.query; // optional
  const m = month || (new Date().getMonth() + 1);
  const y = year || new Date().getFullYear();
  const start = `${y}-${String(m).padStart(2, '0')}-01`;
  const end = `${y}-${String(m).padStart(2, '0')}-31`;
  if (req.session.user.role === 'teacher') {
    const rows = await db.all(`
      SELECT s.student_id, s.name,
        SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) as presents,
        SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) as absents
      FROM students s
      LEFT JOIN attendance a ON a.student_id = s.student_id AND a.date BETWEEN ? AND ?
      GROUP BY s.student_id, s.name
      ORDER BY s.name
    `, start, end);
    res.render('summary_teacher', { rows, month: m, year: y });
  } else if (req.session.user.role === 'student') {
    const sid = req.session.user.id;
    const row = await db.get(`
      SELECT s.student_id, s.name,
        SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) as presents,
        SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) as absents
      FROM students s
      LEFT JOIN attendance a ON a.student_id = s.student_id AND a.date BETWEEN ? AND ?
      WHERE s.student_id = ?
      GROUP BY s.student_id, s.name
    `, start, end, sid);
    res.render('summary_student', { row: row || { presents: 0, absents: 0 }, month: m, year: y });
  } else {
    res.status(403).send('Forbidden');
  }
});

// PDF Export - Professional Attendance Report by Date Range
app.get('/api/export-attendance', requireAuth, async (req, res) => {
  // Only teachers and admins can export
  if (req.session.user.role !== 'teacher' && req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: 'Start date and end date are required' });
  }

  try {
    const db = await openDb();

    // Get all students with their attendance summary for the date range
    const rows = await db.all(`
      SELECT 
        s.student_id,
        s.name,
        SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) as days_present,
        SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) as days_absent,
        COUNT(a.status) as total_marked
      FROM students s
      LEFT JOIN attendance a ON a.student_id = s.student_id AND a.date BETWEEN ? AND ?
      GROUP BY s.student_id, s.name
      ORDER BY s.name
    `, startDate, endDate);

    // Create PDF document
    const doc = new PDFDocument({
      margin: 40,
      size: 'A4',
      info: {
        Title: 'Attendance Report',
        Author: 'AttendancePro™',
        Subject: `Attendance Report from ${startDate} to ${endDate}`
      }
    });

    // Set response headers
    const filename = `Attendance_Report_${startDate}_to_${endDate}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Pipe the PDF to the response
    doc.pipe(res);

    // Colors
    const primaryColor = '#6366f1';
    const successColor = '#10b981';
    const dangerColor = '#f43f5e';
    const darkColor = '#1e293b';
    const grayColor = '#64748b';
    const lightGray = '#f1f5f9';

    // Header Section with gradient-like background
    doc.rect(0, 0, 595, 120).fill(primaryColor);

    // Title
    doc.fontSize(28)
      .fillColor('white')
      .font('Helvetica-Bold')
      .text('ATTENDANCE PRO™', 40, 35, { align: 'center' });

    doc.fontSize(12)
      .fillColor('white')
      .font('Helvetica')
      .text('Professional Attendance Management System', 40, 70, { align: 'center' });

    doc.fontSize(10)
      .text('By Pallav Pradhan | Version 3.0', 40, 90, { align: 'center' });

    // Report Info Box
    doc.roundedRect(40, 140, 515, 80, 8)
      .fill(lightGray);

    doc.fontSize(18)
      .fillColor(primaryColor)
      .font('Helvetica-Bold')
      .text('ATTENDANCE REPORT', 60, 155);

    doc.fontSize(11)
      .fillColor(grayColor)
      .font('Helvetica');

    doc.text(`Report Period:`, 60, 180);
    doc.fillColor(darkColor).font('Helvetica-Bold')
      .text(`${startDate} to ${endDate}`, 150, 180);

    doc.fillColor(grayColor).font('Helvetica')
      .text(`Generated:`, 320, 180);
    doc.fillColor(darkColor).font('Helvetica-Bold')
      .text(`${new Date().toLocaleDateString()}`, 390, 180);

    doc.fillColor(grayColor).font('Helvetica')
      .text(`Total Students:`, 60, 200);
    doc.fillColor(darkColor).font('Helvetica-Bold')
      .text(`${rows.length}`, 150, 200);

    // Calculate totals
    let totalPresent = 0;
    let totalAbsent = 0;
    rows.forEach(row => {
      totalPresent += row.days_present || 0;
      totalAbsent += row.days_absent || 0;
    });

    doc.fillColor(grayColor).font('Helvetica')
      .text(`Total Present Days:`, 320, 200);
    doc.fillColor(successColor).font('Helvetica-Bold')
      .text(`${totalPresent}`, 430, 200);

    doc.fillColor(grayColor).font('Helvetica')
      .text(`Total Absent Days:`, 460, 200);
    doc.fillColor(dangerColor).font('Helvetica-Bold')
      .text(`${totalAbsent}`, 555, 200);

    // Table Header
    const tableTop = 245;
    const tableLeft = 40;
    const colWidths = [35, 70, 160, 65, 60, 60, 65];

    // Table header background
    doc.rect(tableLeft, tableTop, 515, 28).fill(primaryColor);

    // Table headers
    doc.fontSize(9)
      .fillColor('white')
      .font('Helvetica-Bold');

    let xPos = tableLeft + 8;
    const headers = ['S.No', 'Student ID', 'Student Name', 'Present', 'Absent', 'Total', 'Attendance'];
    headers.forEach((header, i) => {
      doc.text(header, xPos, tableTop + 9, { width: colWidths[i] - 10, align: 'left' });
      xPos += colWidths[i];
    });

    // Table rows
    let yPos = tableTop + 28;
    const rowHeight = 24;

    rows.forEach((row, index) => {
      // Check if we need a new page
      if (yPos > 750) {
        doc.addPage();
        yPos = 50;

        // Add table header on new page
        doc.rect(tableLeft, yPos, 515, 28).fill(primaryColor);
        doc.fontSize(9).fillColor('white').font('Helvetica-Bold');
        let headerX = tableLeft + 8;
        headers.forEach((header, i) => {
          doc.text(header, headerX, yPos + 9, { width: colWidths[i] - 10, align: 'left' });
          headerX += colWidths[i];
        });
        yPos += 28;
      }

      // Alternate row background
      if (index % 2 === 0) {
        doc.rect(tableLeft, yPos, 515, rowHeight).fill('#f8fafc');
      } else {
        doc.rect(tableLeft, yPos, 515, rowHeight).fill('white');
      }

      // Row border
      doc.rect(tableLeft, yPos, 515, rowHeight).stroke('#e2e8f0');

      // Calculate percentage
      const total = (row.days_present || 0) + (row.days_absent || 0);
      const percentage = total > 0 ? ((row.days_present / total) * 100).toFixed(1) : '0.0';

      // Row data
      doc.fontSize(9).font('Helvetica').fillColor(darkColor);

      let cellX = tableLeft + 8;

      // S.No
      doc.text((index + 1).toString(), cellX, yPos + 8, { width: colWidths[0] - 10 });
      cellX += colWidths[0];

      // Student ID
      doc.font('Helvetica-Bold').fillColor(primaryColor)
        .text(row.student_id, cellX, yPos + 8, { width: colWidths[1] - 10 });
      cellX += colWidths[1];

      // Student Name
      doc.font('Helvetica').fillColor(darkColor)
        .text(row.name, cellX, yPos + 8, { width: colWidths[2] - 10 });
      cellX += colWidths[2];

      // Days Present
      doc.fillColor(successColor).font('Helvetica-Bold')
        .text((row.days_present || 0).toString(), cellX, yPos + 8, { width: colWidths[3] - 10 });
      cellX += colWidths[3];

      // Days Absent
      doc.fillColor(dangerColor).font('Helvetica-Bold')
        .text((row.days_absent || 0).toString(), cellX, yPos + 8, { width: colWidths[4] - 10 });
      cellX += colWidths[4];

      // Total
      doc.fillColor(grayColor).font('Helvetica')
        .text((row.total_marked || 0).toString(), cellX, yPos + 8, { width: colWidths[5] - 10 });
      cellX += colWidths[5];

      // Attendance Percentage with color coding
      const pctValue = parseFloat(percentage);
      let pctColor = dangerColor;
      if (pctValue >= 75) pctColor = successColor;
      else if (pctValue >= 50) pctColor = '#f59e0b';

      doc.fillColor(pctColor).font('Helvetica-Bold')
        .text(`${percentage}%`, cellX, yPos + 8, { width: colWidths[6] - 10 });

      yPos += rowHeight;
    });

    // Footer
    const footerY = Math.min(yPos + 30, 780);

    doc.fontSize(9)
      .fillColor(grayColor)
      .font('Helvetica')
      .text('This report was automatically generated by AttendancePro™ Management System',
        40, footerY, { align: 'center', width: 515 });

    doc.text('© 2026 Designed for Teacher Pallavi Pradhan | All Rights Reserved',
      40, footerY + 15, { align: 'center', width: 515 });

    // Finalize the PDF
    doc.end();

  } catch (error) {
    console.error('Error generating attendance report:', error);
    res.status(500).json({ error: 'Error generating report' });
  }
});

// Start server after DB init
initDb().then(() => {
  app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
}).catch(err => console.error(err));

// Dev-only debug endpoint to inspect session
app.get('/_debug_session', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({ session: req.session }, null, 2));
});
