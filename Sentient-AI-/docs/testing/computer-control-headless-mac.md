# Testing computer control on the headless test Mac

This is the real-machine check for `computer_control` (design:
`docs/superpowers/specs/2026-09-24-computer-control-design.md`, section 7).
The unit tests run only against fakes, so nothing in CI clicks, types or
reads a screen. This checklist does, **only on the owner's throwaway test
Mac**. Do not run `--act` on a machine you care about: it sends real mouse
and keyboard events.

What gets exercised: the real `MacBackend` (pyobjc: accessibility tree,
Quartz events, NSWorkspace) under the real `ComputerToolkit`, with every
hard rule in the path. The script is `backend/scripts/computer_control_smoke.py`.

This is the low-level smoke test. To test the whole product live on the
same Mac (native install, setup wizard, Telegram, browser and computer
control through the agent, approvals, stop, cost lines) with real Gemini,
Claude and GPT keys, follow [headless-mac-full-test.md](headless-mac-full-test.md).

## 0. What you need

- The test Mac (macOS 13 or later), logged in to a GUI session with an
  admin account. A Mac at the login window or lock screen cannot be
  controlled; Crawler refuses to act there anyway.
- Another Mac to reach it with Screen Sharing.
- A display for the test Mac. A headless Mac has no framebuffer, so screen
  capture comes back black and some apps never lay out their windows. Use
  one of these:
  - an HDMI dummy plug (cheapest and most reliable),
  - a virtual display from an app such as BetterDisplay,
  - Screen Sharing's High Performance mode (Apple silicon on both ends,
    macOS 14 or later), which creates a virtual display for the session.

## 1. Get Screen Sharing in

On the test Mac, once (locally, or over SSH):

```sh
# System Settings > General > Sharing > Screen Sharing: on.
# Over SSH instead:
sudo launchctl enable system/com.apple.screensharing
sudo launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.screensharing.plist
```

From the other Mac: Finder > Go > Connect to Server > `vnc://<test-mac>.local`,
or open the Screen Sharing app. Log in to the desktop.

Keep it awake for the whole test (in a Terminal on the test Mac):

```sh
caffeinate -dimsu &
```

## 2. Get the code and a Python for it

In a Terminal on the test Mac (through Screen Sharing):

```sh
git clone https://github.com/krishcodes1/Sentient-AI-.git
cd Sentient-AI-/Sentient-AI-/backend
git checkout main
git pull
python3 -m venv .venv-cc
. .venv-cc/bin/activate
# Full backend deps (includes pyobjc on macOS):
pip install -r requirements.txt
# ...or only what this test imports (faster):
# pip install structlog "pyobjc-framework-ApplicationServices>=10,<13" \
#     "pyobjc-framework-Quartz>=10,<13" "pyobjc-framework-Cocoa>=10,<13"
```

## 3. Find the binary that needs the grants

With the venv active:

```sh
python3 -c "import sys,os;print(os.path.realpath(sys.executable))"
```

This prints the real interpreter behind the venv, for example
`/opt/homebrew/Cellar/python@3.12/3.12.x/Frameworks/Python.framework/Versions/3.12/bin/python3.12`
or `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12`.
The smoke script prints the same path on its first line.

Framework builds of Python start that interpreter as the `Python.app`
beside it: a running process shows up in `ps` as
`.../Versions/3.x/Resources/Python.app/Contents/MacOS/Python` (seen with
the python.org 3.13 build). If a grant to the `bin/python3.x` path does not
take, add that `Python.app` as well.

## 4. Grant Accessibility and Screen Recording

System Settings > Privacy & Security:

1. **Accessibility** > `+` > press cmd+shift+G, paste the path from step 3,
   Open, and switch it on.
2. **Screen & System Audio Recording** (called Screen Recording before
   macOS 15) > `+` > the same path > on. The smoke test does not capture the
   screen, but `desktop.screenshot` and `for_model_image` will, so grant it
   now.
3. **Also add Terminal** (Applications > Utilities > Terminal) to both
   lists. When a program is started from Terminal, macOS checks the grant of
   Terminal (the app responsible for it), not the Python binary. The Python
   grant is the one the Crawler service uses when it is not started from a
   Terminal window.

`python3 scripts/computer_control_smoke.py --request-permission` shows
macOS's Accessibility prompt and opens the pane for you if the grant is
missing. After changing a grant, start the script again: macOS reports trust
per process.

## 5. Dry run (observes only)

```sh
python3 scripts/computer_control_smoke.py
```

It sends no input: the backend is wrapped so any click, key, typing, scroll,
app launch or window switch raises instead of reaching macOS, and the
refusal checks use the toolkit's `precheck`, which calls no backend. Expect:

```
Python binary that needs the grants: /.../python3.12
Display: main display 1920x1080
[PASS] backend available - pyobjc loaded
[PASS] Accessibility permission - granted
[PASS] list apps - N app(s), front: 'Terminal'; ...
[PASS] list windows - N window(s)
[PASS] outline the front window - app 'Terminal', N ref(s), 0 secure field(s) redacted
      - window "..." [ref=d1]
      ...
[PASS] refuse to open Terminal - {... 'rule': 'blocked_app' ...}
[PASS] refuse input to 'Terminal' - {... 'rule': 'blocked_app' ...}
[SKIP] refuse typing into a password field - ...
Dry run finished: nothing was clicked, typed or opened. Use --act for the rest.
```

If `Display:` says there is no main display, fix step 0 before going on.

## 6. Act run (sends real input)

```sh
python3 scripts/computer_control_smoke.py --act
```

It waits 5 seconds (press ctrl+C to stop), then drives the Mac. Do not touch
the mouse or keyboard while it runs. Each line is a check:

| Check | What happens | Rule it proves |
|---|---|---|
| open TextEdit | `open_app TextEdit`; if the Open panel shows, cmd+n for a new document | open_app, activation |
| outline TextEdit | reads the document window; finds the text area's ref | AX tree walk, refs |
| type 'hello from Crawler' | types into the text area by ref | focus by ref, Unicode typing |
| the text is in the document | a fresh outline shows the value | outline values |
| press cmd+a | selects all | key grammar, modifiers released |
| cmd+s opens the Save sheet / escape cancels the Save sheet | the save dialog opens and is cancelled | spec section 7: save-dialog cancel |
| Stop cancels the next action | sets the per-user cancel flag; the next key press is refused and never sent | kill switch (`/stop`, `POST /api/agent/stop`) |
| refuse to open Terminal (live) | `open_app Terminal` is refused before any backend call | blocked apps |
| Safari test page shows a secure field | opens a local page with a password input in Safari; the outline shows `value=[redacted]` | secure values never read |
| refuse typing into the password field | typing by its ref is refused and never sent | never type into a secure field |

Exit code 0 means every check passed; 1 means one failed; 2 means the Mac
is not set up (not macOS, pyobjc missing, Accessibility not granted).

Afterwards close TextEdit's document without saving (cmd+w, then Delete)
and Safari's test tab. Nothing else is changed.

## 7. Unit tests on the real Mac

The Mac backend's tests use fakes everywhere, and one of them also checks
the real pyobjc symbols and constants (skipped where pyobjc is missing):

```sh
pip install -r requirements-dev.txt
python3 -m pytest tests/test_computer_backend_mac.py tests/test_computer_toolkit.py \
    tests/test_computer_rules.py tests/test_computer_control_smoke.py -q
```

## 8. Troubleshooting

- **`state is 'denied'` after granting.** Quit and rerun the script. If you
  ran it from Terminal, Terminal needs the grant too (step 4.3). A Python
  upgrade changes the binary path: grant the new one.
- **The outline is empty or the display line says there is none.** Attach a
  display or virtual display (step 0) and make sure the session is not at
  the lock screen.
- **TextEdit shows an iCloud Open panel.** The script presses cmd+n for a
  new document. If the panel stays, click New Document once by hand and
  rerun.
- **No secure field in Safari.** WebKit builds its accessibility tree on the
  first request; rerun `--act` once. If it still fails, copy the printed
  outline lines into the report.
- **A check fails.** Copy the whole output (it holds no secrets: password
  values are never read) into the PR or the team channel.

## 9. Undo the grants when done (optional)

```sh
tccutil reset Accessibility
tccutil reset ScreenCapture
```

Not covered here: `/stop` from Telegram and the web Stop button
(`POST /api/agent/stop`) end to end (the script sets the same per-user
cancel flag they set; the full guide's row 5g tests them live), and the
Windows backend, which gets the same script-style check on the team's
Windows VM.
