# Placetel AI - Webex Embedded App

Complete redesigned architecture for Webex embedded app with proper user role management, authorization, and AI call forwarding.

## Architecture Overview

### Three Main Pages

1. **Live Panel** (`/live`)
   - Real-time call monitoring
   - Displays incoming AI-forwarded calls
   - Shows structured call information (customer name, number, email, concerns, tasks)
   - Animated equalizer bars during active calls
   - Different behavior for single users vs user groups

2. **History Panel** (`/history`)
   - View past call history from Webex
   - Access call recordings
   - Transcribe and attach recordings
   - Expandable details for each call

3. **Authorization Panel** (`/authorization`)
   - Admin-only access
   - Manage internal users, user groups, and external users
   - Generate POST API endpoints with secure tokens
   - One-click copy to clipboard

### Call Flow

#### For Single Users (Internal/External)
1. AI call completes and forwards to human agent
2. POST request sent to user's unique endpoint
3. Call summary appears immediately in Live panel
4. Animated equalizer shows call is active

#### For User Groups
1. AI call completes and forwards to group
2. POST request sent to group's unique endpoint
3. All group members see caller number in Live panel
4. **No summary shown yet** - waiting for pickup
5. First user to click "Pick Up Call" receives the full summary
6. Summary removed from other group members' views
7. Assigned user sees animated equalizer and full call details

## Required Webex Scopes

### Embedded App SDK v2
The app uses **Webex Embedded App SDK v2** exclusively. Make sure your app integration has the following scopes:

### Required Scopes
1. **spark:calls_read** - Read call information
2. **spark:calls_write** - Manage calls
3. **spark:people_read** - Read user information
4. **spark:telephony_read** - Read telephony configuration
5. **spark:telephony_write** - Manage telephony settings

### Admin Scopes (for Authorization Panel)
6. **spark-admin:people_read** - List all users
7. **spark-admin:workspaces_read** - List user groups/workspaces
8. **spark-admin:telephony_config_read** - Read telephony configuration

### Compliance/Recording Scopes (for History Panel)
9. **spark-compliance:recordings_read** - Access call recordings
10. **spark-compliance:call_histories_read** - Read call history (CDR data)

## Technical Architecture

### Webex SDK v2 Authentication
**There is NO separate login/authentication panel** in this app. Authentication is handled automatically by the Webex Embedded App SDK v2:
- When a user opens the embedded app, the SDK automatically authenticates them through Webex
- No username/password entry needed
- User identity is fetched via `/api/auth/me` endpoint
- Admin vs regular user roles are detected automatically from Webex user data

If you don't see a login screen, that's correct! The app starts directly on the Live panel.

### Socket.IO Real-Time Communication
**Socket.IO** is used for browser-based real-time updates in the embedded app UI. This works for ALL users - whether they're:
- **Admin with full Webex suite** - They see all features including Authorization panel
- **Regular users with only Webex Calling** - They see Live and History panels

Socket.IO is NOT about client types - it's just the web technology that pushes live call updates to the browser UI immediately without page refresh. Every user who opens the embedded app in their browser automatically connects via Socket.IO to receive real-time notifications when calls arrive.

## Setup Instructions

### 1. Configure Webex Integration
Go to [Webex Developer Portal](https://developer.webex.com/) and create/update your embedded app with the scopes listed above.

### 2. Set Environment Variables
```bash
export WEBEX_BEARER="your-webex-bearer-token"
```

Update this token in `app.py` every login session (valid for 12 hours).

### 3. Install Dependencies
```bash
pip install flask flask-socketio werkzeug requests pandas openpyxl
```

### 4. Run the Application
```bash
python app.py
```

The app will run on `http://localhost:5000`

### 5. Expose with ngrok (for testing)
```bash
ngrok http 5000
```

Use the ngrok URL in your Webex embedded app configuration.

## Usage Guide

### For Admins

1. **Access Authorization Panel**
   - Log in to the embedded app
   - Navigate to "Authorization" tab (visible only to admins)

2. **Generate API Endpoints**
   - View list of internal users
   - View list of user groups (workspaces)
   - Click "Generate" next to any user/group
   - URL is automatically copied to clipboard
   - Share this URL with your AI system integration

3. **Add External Users**
   - Enter phone number or external user ID
   - Enter display name
   - Click "Generate External User Endpoint"
   - URL is copied to clipboard

### For Regular Users

1. **Monitor Live Calls**
   - Open the "Live" tab
   - Wait for incoming AI-forwarded calls
   - View caller information and AI summary
   - Animated bars indicate active call

2. **Group Call Handling**
   - See incoming group call with caller number
   - Click "Pick Up Call" to accept
   - Summary appears after pickup
   - Other group members no longer see this call

3. **Review History**
   - Navigate to "History" tab
   - Browse past calls grouped by caller
   - Click on call to see details
   - Download recordings or transcribe

### Testing with Simulator

1. **Access Simulator**
   - Navigate to `/simulator` in your browser
   - Not linked from main app (testing tool only)

2. **Configure API Endpoint**
   - Paste the POST URL from Authorization panel
   - Optionally add Bearer token

3. **Send Test Call**
   - Fill in customer information
   - Add concerns and tasks
   - Click "Send AI Call Summary"
   - Check Live panel to see the call appear

## API Endpoints

### User Management
- `GET /api/auth/me` - Get current user info
- `GET /api/users/list` - List all users (admin)
- `GET /api/groups/list` - List all groups (admin)

### Authorization
- `POST /api/auth/generate` - Generate API endpoint for user/group
- `POST /api/forward/<token>` - Receive AI call summary (external)

### Call Management
- `POST /api/call/pickup` - User picks up group call
- `GET /api/pending_calls/<user_id>` - Get pending calls for user

### Call History
- `GET /api/calls/history` - Get call history from Webex
- `GET /api/calls/recordings` - Get recordings for call session
- `GET /api/recordings/<rec_id>/download` - Download recording
- `POST /api/recordings/<rec_id>/transcribe` - Transcribe recording

## Technical Details

### Technologies
- **Backend**: Flask + Flask-SocketIO
- **Frontend**: Vanilla JavaScript with Webex SDK v2
- **Real-time**: Socket.IO for live updates
- **Storage**: In-memory + file-based persistence

### Architecture Improvements
- ✅ Separated Live, History, and Authorization pages
- ✅ Proper user role detection (admin vs regular user)
- ✅ Socket.IO room-based messaging (per-user channels)
- ✅ Secure token-based API endpoints
- ✅ Group call handling with pickup mechanism
- ✅ Animated UI with proper state management
- ✅ Only Webex SDK v2 (no deprecated code)

### Security
- Bearer token authentication for Webex APIs
- Unique secure tokens for each user/group endpoint
- Token persistence to disk for recovery
- Room-based Socket.IO messaging (users only see their calls)

## Troubleshooting

### "Webex SDK v2 not loaded"
- Check that `@webex/embedded-app-sdk@2` is loading correctly
- Verify CSP headers allow Webex domains

### "You do not have admin permissions"
- Ensure user has `Full_Admin` or `User_Admin` role in Webex
- Check `/api/auth/me` response for roles

### Calls not appearing in Live panel
- Verify Socket.IO connection in browser console
- Check that user joined their room (look for `User <id> joined room` in logs)
- Verify POST endpoint token is valid

### Group calls showing summary immediately
- Check `target_type` in `/api/forward/<token>` - should be "group"
- Verify `show_summary` is `false` in Socket.IO emission

## Files Structure

```
TestPlugInWebex/
├── app.py                      # Main Flask application
├── templates/
│   ├── live.html              # Live call monitoring page
│   ├── history.html           # Call history page
│   ├── authorization.html     # Admin authorization management
│   ├── simulator.html         # Testing simulator (not linked)
│   └── index.html             # Legacy (redirects to live)
├── static/
│   ├── app.css                # Main stylesheet
│   └── bot.png                # AI bot idle icon
├── data/
│   ├── auth/                  # Generated auth tokens
│   ├── transcripts/           # Call transcripts
│   └── recordings/            # Call recordings
├── simulator.py               # CLI simulator (legacy)
├── simulator_api.py           # Simulator API (legacy)
└── README.md                  # This file
```

## Next Steps

1. **Get Webex developer token** with required scopes
2. **Update WEBEX_BEARER** in app.py
3. **Run ngrok** to expose local server
4. **Configure embedded app** in Webex with ngrok URL
5. **Test with simulator** to verify flow
6. **Generate real endpoints** in Authorization panel
7. **Integrate with your AI system**

## Support

For issues or questions about Webex scopes or embedded app configuration, refer to:
- [Webex Embedded Apps SDK](https://developer.webex.com/docs/embedded-apps)
- [Webex API Documentation](https://developer.webex.com/docs/api/getting-started)
- [Flask-SocketIO Documentation](https://flask-socketio.readthedocs.io/)
