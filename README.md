# Attendance App by Pallav Pradhan

A web-based attendance management system for tracking student attendance.

## Features

- 📚 Admin dashboard for uploading students
- 👩‍🏫 Teacher dashboard for marking attendance
- 👨‍🎓 Student view for checking attendance records
- 📅 Calendar view with monthly summaries
- 📊 Attendance statistics and reports
- 📱 Mobile-responsive design

## Default Credentials

- **Admin**: `admin` / `admin123`
- **Teacher**: `teacher` / `teacher123`
- **Student**: `student` / `student123`

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   npm start
   ```

3. Open http://localhost:3000

## Deployment

This app can be deployed to:
- Render (recommended for free hosting)
- Railway
- Heroku
- Any Node.js hosting platform

### Deploy to Render

1. Push your code to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com/)
3. Click "New" → "Web Service"
4. Connect your GitHub repository
5. Render will automatically detect the `render.yaml` configuration
6. Click "Create Web Service"

### Environment Variables

Set these in your hosting platform:
- `SESSION_SECRET`: Random secret for session encryption
- `NODE_ENV`: Set to `production`

## Technologies

- Node.js & Express
- SQLite database
- EJS templating
- Bcrypt for password hashing
- Excel/CSV file uploads

## Author

Created by Pallav Pradhan (@pallav199)

## License

This project is for personal use.
