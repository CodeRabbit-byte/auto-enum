README.txt
Run test.py if you receive Example Domain means it works and you are ready to go.
required installation:
sudo apt update && sudo apt install -y \
  hydra \
  gobuster \
  chromium-driver \
  chromium \
  python3-selenium \
  seclists \
  wordlists \
  curl \
  wget
python installation:pip install selenium requests
wordlist installation: 
    | Wordlist       | Path                                            | Purpose             |
| -------------- | ----------------------------------------------- | ------------------- |
| Dirb wordlist  | `/usr/share/wordlists/dirb/common.txt`          | For Gobuster        |
| Usernames list | `/usr/share/wordlists/usernames.txt` *(custom)* | For Hydra user list |
| RockYou        | `/usr/share/wordlists/rockyou.txt`              | For Hydra passwords |
 You may need to create a simple usernames.txt file if it’s missing: