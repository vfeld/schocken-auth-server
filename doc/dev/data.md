User data:
- user-id (unique)
- user-name-first
- user-name-last
- email
- email-status: confirmed,unconfirmed
- user-status: active,inactive
- primary-auth-method: [credential,github,google,...]
- secondary-auth-method: [none, otp]

User Credentials
- user-id (unique)
- login-name
- hashed password

OTP Secrets
- user-id
- secret

Role Bindings
- binding-id (unique)
- user-id
- role

One-time-token data:
- type: register-day-0-user
  - token, status: valid, invalid, created-at, next-step: final
- type: invite-user
  - token, user name, email, created-at
- type: recover-password
  - token, user-id, created-at, next-step: (final, otp)
- type: reactivate-user
  - token, user-id, created-at, next-step: final
- type: change-password
  - token, user-id, created-at, next-step: (final, otp)

Session data
- session-id
- role-binding-id
- created-at

Global data:
- domain name of auth-provider server
- Session live time
- One-time link live time per type
- password hashing parameter
- DB password