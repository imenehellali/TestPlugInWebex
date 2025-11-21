# Call Detection Debugging Guide

## Problem
The `sidebar:callStateChanged` event is NOT firing when you make/receive Webex calls, even though:
- ✓ SDK initializes successfully
- ✓ `spark:xsi` scope is added
- ✓ Socket.IO connects
- ✓ Code matches official Webex example exactly

## Root Cause
This is almost certainly a **Webex Embedded App manifest configuration issue**, NOT a code issue.

## What to Check in Webex Developer Portal

### 1. App Type & Context
Go to: https://developer.webex.com/my-apps

**Check your embedded app configuration:**
- App Type: Must be "Embedded App"
- Context: Must include **"Sidebar"** (NOT just "In-Meeting" or "Spaces")
- Location: "Sidebar" must be enabled

### 2. Capabilities / Features
**Your app manifest MUST declare it wants call events:**
- Look for "Capabilities" or "Features" section
- Must enable: **"Calling"** or **"Call Monitoring"** or **"Access calling features"**
- Without this capability, the SDK will never fire `sidebar:callStateChanged` events

### 3. OAuth Scopes (Integration)
**Required scopes for calling:**
- `spark:xsi` - Access Webex calling resources ✓ (you added this)
- `spark:calls_read` - Read call information
- `spark:calls_write` - Manage calls

**Check if all are enabled** in your integration's OAuth scopes.

### 4. Valid Domains
**Your ngrok URL must be whitelisted:**
- Check "Valid Domains" section
- Add your ngrok domain (without https://)
- Example: `servantlike-thermochemically-maison.ngrok-free.dev`

### 5. Start URL
**Must point to your embedded app:**
- Start URL: `https://your-ngrok-url/live` (or wherever your app is served)
- Must be HTTPS (ngrok provides this)

## Expected Manifest Structure

Your embedded app manifest should look something like this:

```json
{
  "manifestVersion": "1.0",
  "appType": "embedded",
  "contexts": ["sidebar"],
  "capabilities": {
    "calling": {
      "enabled": true
    }
  },
  "validDomains": [
    "your-ngrok-url.ngrok-free.dev"
  ],
  "startURL": "https://your-ngrok-url.ngrok-free.dev/live"
}
```

## How to Verify

### In Browser Console:
When you open your app in Webex sidebar, check console logs:

```
[INIT] Creating Webex Application instance...
[INIT] SDK is ready!
[INIT] Now listening for events!
[INIT] Registering call event listener...
[INIT] Available events on SDK: [...should include 'on', 'off', 'emit'...]
[INIT] ===== SDK FULLY INITIALIZED =====
```

### When Making a Call:
**Expected:** You should see this log:
```
[EVENT] ===== sidebar:callStateChanged FIRED =====
[EVENT] Call data: { ... }
```

**If you DON'T see this:** The problem is NOT in the code - it's in the app configuration.

## Common Issues

### Issue 1: "I added spark:xsi but still no events"
**Solution:** The scope alone isn't enough. The app manifest must declare "calling" capability.

### Issue 2: "The test button works but real calls don't"
**Solution:** Test button bypasses the SDK - it just calls your UI function directly. This confirms UI works but SDK events aren't firing.

### Issue 3: "I'm testing in desktop Webex app"
**Solution:** Make sure you're opening it as a **Sidebar app**, not as a regular web page or in-meeting panel.

### Issue 4: "Using Webex web app instead of desktop"
**Solution:** Some calling features only work in Webex desktop app. Try desktop if you're using web.

## Official Documentation
- [Embedded Apps Framework](https://developer.webex.com/docs/embedded-apps-framework-sidebar-api-quick-start)
- [Sidebar Call Events](https://developer.webex.com/docs/embedded-apps-framework-sidebar-api-reference#sidebar-call-state-changed)
- [OAuth Scopes](https://developer.webex.com/docs/integrations#scopes)

## Next Steps

1. **Go to Webex Developer Portal**
2. **Find your embedded app**
3. **Edit the manifest/configuration**
4. **Enable "Calling" capability**
5. **Save and redeploy**
6. **Restart Webex desktop app** (sometimes needed to pick up new manifest)
7. **Try making a call again**

The code is correct. The configuration is the issue.
