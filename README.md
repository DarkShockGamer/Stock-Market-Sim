# Stock Idle

A tiny, semi-idle stock market simulator. Prices fluctuate on their own, you buy and sell
shares of real companies (fictional prices), and buy upgrades like dividends, an auto-trader and
lower fees. Progress is saved in your browser (localStorage), and you earn a reduced amount while away.

## Run locally
```
node server.js
```
Open http://localhost:3000 (no npm install needed).

## Deploy: GitHub + Railway
1. Create a GitHub repo and push these files (`git init && git add . && git commit -m "init" && git push`).
2. On railway.app: **New Project -> Deploy from GitHub repo** -> pick the repo.
3. Railway detects Node and runs `npm start`. Open **Settings -> Networking -> Generate Domain**.

## Small corner window
- Click the **Pop out** button in the game, or
- Install it: in Chrome open the site, menu -> **Cast, save and share -> Install page as app**, then resize it, or
- Launch as a mini app window (Windows example):
  `chrome.exe --app=https://YOUR-APP.up.railway.app --window-size=360,520 --window-position=1540,520`
  (Mac: `open -na "Google Chrome" --args --app=URL --window-size=360,520`)

Chrome remembers an app window's size and position after you move it to the bottom-right once.
Tip: browsers throttle background tabs; keep the window visible (or use the offline earnings) for best idle results.

Not financial advice. It's a game.
