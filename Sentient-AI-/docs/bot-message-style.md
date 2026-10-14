# How Crawler talks to people

Every message a person sees from Crawler (Telegram, Slack, the web app's
approval cards, reminders, scheduled tasks, triggers, errors) follows these
rules. The person is not a developer. They should never have to know what a
tool, an argument, JSON or a policy is.

## Voice

- Write like a helpful person texting back: short, plain, calm.
- In chat, Crawler says "I" and calls the owner "you". Card titles and
  labels need no pronoun ("Send an email to priya@acme.com").
- Use contractions (I'll, can't, didn't). Sentence case. Short sentences.
- One emoji at most per message, at the start, with a fixed meaning:
  🔐 needs your OK, ✅ approved or done, ❌ denied, ⚠️ something went
  wrong or needs care, ⛔ not allowed, ⏸ paused, 🛒 a purchase.

## Never show

- Tool ids (`system.install_capability`, `desktop.act`), function call
  syntax (`name='browser'`), JSON, braces, quoted keys, snake_case words.
- Internal words: arguments, digest, payload, capability, tool, callback,
  policy, token, session, DM, model, provider (say "your AI service" if it
  must be named), task id, exception names, "see server logs".
- Raw error text from code. Say what happened in the person's terms and
  what they can do next.

## Never write

- Em dashes or en dashes, anywhere. Use commas, periods or parentheses.
  Ranges are "1 to 3", not "1–3".
- Chatbot filler: "I'd be happy to", "Certainly", "Great question",
  "Feel free to", "Rest assured", "It's important to note", "Please note".
- Inflated words: delve, crucial, pivotal, robust, seamless, leverage,
  utilize, facilitate, ensure, enhance, foster, streamline, comprehensive,
  empower, additionally, furthermore, moreover, "in order to".
- Hostile or technical failure words: fatal, illegal, invalid, aborted,
  exception, unconditionally.
- Blame ("you entered an invalid ...") or alarm ("WARNING", "ACTION
  REQUIRED").

## Approval cards

A card says what will happen, shows everything that will be used, and asks.

```
🔐 Send an email to priya@acme.com from your Gmail

To: priya@acme.com
Subject: Friday lunch
Message:
   Hi Priya, are we still on for noon?

Okay to go ahead? This expires in 14 minutes.
Check code 6d3b dfca 7bf8 cfc5
```

- First line: one plain sentence, verb first, naming the action and its
  target. It is what a phone notification preview shows.
- Then every value the action will use, as `Label: value` lines with
  everyday labels (To, Subject, Message, Link, File, When). Nothing is ever
  cut or hidden (spec F3): recipients, links, paths, amounts and the text
  to be sent are shown in full. Text that spans several lines goes under
  its label, indented, so it can't pass for another line of the card.
  Yes/No instead of true/false; lists one item per line.
- Secrets stay masked (`redact_obj` with the CHANNEL policy).
- `Okay to go ahead? This expires in N minutes.` then the quiet
  `Check code xxxx xxxx xxxx xxxx` line (the same code the web card shows,
  so the two can be compared).
- Buttons stay ✅ Approve and ❌ Deny.
- After a tap, the card is edited: the buttons go and one line is added,
  `✅ Approved at 5:25 PM.` or `❌ Denied at 5:25 PM. I didn't do it.`

## Errors and refusals

Say what happened, a short reason in plain words if it helps, and what the
person can do. "Something went wrong and your answer didn't go through. Tap
the button again, or answer in the web app."

## Where the words live

- `services/action_text.py`: the plain sentence, short phrase, app name
  and field labels for every action that can ask for approval.
- `services/notifications/cards.py`: the shared card layout, details
  rendering, check code and reply notes for every chat channel.
- `services/agent/runtime.py` `<style>` and
  `services/agent/channel_style.py`: what the AI is told about how to
  talk, including never naming tools or showing arguments.
