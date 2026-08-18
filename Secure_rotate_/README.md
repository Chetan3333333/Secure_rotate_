# SecureRotate

SecureRotate is a working prototype for an AI-based database password expiry recommendation and automated rotation system. It demonstrates the full judging flow: credential monitoring, ML-style risk scoring, recommendation explanation, seven-day stakeholder notification, controlled password rotation, connectivity verification, and audit history.

## Run Locally

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:8000
```

The app uses only Python standard-library modules and creates a local `securerotate.db` SQLite database on first run.

## Pages

- User portal: `http://127.0.0.1:8000/user`
- Admin dashboard: `http://127.0.0.1:8000/admin`

For a real-life style test, share the user portal with friends on the same deployed app. They submit database credential metadata, and you review the records in the admin dashboard.

## What Works

- Synthetic enterprise credential inventory with production, staging, and development accounts.
- Random-forest-surrogate risk predictor using expiry, environment, privilege, dependencies, failures, age, usage, account type, and criticality.
- Recommendation engine that maps risk into Monitor, Schedule Rotation, Rotate Within 72 Hours, Rotate Within 24 Hours, or Immediate Rotation.
- Explainability panel showing the strongest factors behind each recommendation.
- Automatic seven-day notification generation with acknowledgement.
- Controlled rotation workflow that generates a strong secret, stores only a salted PBKDF2 hash, updates expiry, verifies connectivity, resolves alerts, and writes audit records.
- Interactive dashboard, explorer, recommendation center, rotation center, notifications, audit, and analytics.
- User-facing submission portal where people can add credential details for admin review.

## Demo Script

1. Open `/user` and submit one credential with expiry within 7 days.
2. Open `/admin` and show that the submitted credential appears in the admin dashboard.
3. Show the risk probability, top factors, recommended action, stakeholders, and seven-day notification logic.
4. Move to Rotation and click `Approve & Rotate Selected`.
5. Show the live progress, verification result, updated expiry, resolved notification, and new audit event.
6. Use filters such as `Production` and `Critical` to prove the dashboard is interactive.

## Security Notes

This prototype never displays generated passwords. It stores a salted PBKDF2 hash and a vault-style reference (`vault://...`) to model real enterprise secret handling. A production version would replace the demo connector with a database-specific connector and integrate with a vault such as CyberArk, HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.
