JOB MART FULL VERSION 3.0

This is a single-file FastAPI Job Mart upgrade based on the original application.

Existing features preserved:
Register/Login/Logout, password login, demo OTP login, password reset,
job search, country/job-type filters, job details, job applications,
employer posting, My Jobs, applicants, dashboard, API endpoints,
SQLite, responsive UI, mobile menu, AI customer support.

Added:
- Profile editing
- Resume upload
- Resume builder / print-to-PDF
- Saved/bookmarked jobs
- Application status workflow
- Employer accept/reject/shortlist/interview statuses
- Job edit/delete/close/reopen
- Notifications
- Email OTP integration
- SMS OTP integration through optional Twilio settings
- Advanced job filters
- Job categories
- Company profiles
- Report/flag jobs
- Fraud/scam warning score
- Admin panel
- User block/unblock
- AI customer support
- AI resume assistance
- AI application assistance
- AI job recommendations
- Stronger password hashing/session expiry
- Upload validation
- Health endpoint

IMPORTANT PRODUCTION NOTES:
1. Set ADMIN_PASSWORD to a strong secret before deployment.
2. Set OPENAI_API_KEY for live AI. Without it, customer support has a safe fallback.
3. Configure SMTP for real email OTP.
4. Configure Twilio variables for real SMS OTP.
5. SQLite is retained for compatibility with the original project. For a serious multi-instance production deployment, move the data layer to PostgreSQL and uploads to object storage.
6. The resume builder uses the browser print dialog; selecting "Save as PDF" creates the PDF on the user's device.
7. APK packaging is a separate Android build step. This backend is already mobile-responsive and can be wrapped as an Android app.
8. Do not expose .env or API keys in GitHub.
9. After replacing main.py, keep the existing job_mart.db if you want to preserve existing accounts/jobs. The code performs compatibility migrations.
