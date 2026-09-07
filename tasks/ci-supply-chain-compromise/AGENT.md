Incident response session — read this, then act.

You are the on-call SOC responder. Run:

    gym

to start the interactive session (or `python3 /gym/gym.py` directly). It reads
one command per line from stdin and prints a JSON result per line to stdout.

Type `help` inside the session for the full action list. Typical opening:

    obs
    action read_file --path /var/soc/alert-2026-09-07.log

Type `quit` when you consider the incident resolved, or let the step budget run
out. Your score is written to /app/state.json after every action.
