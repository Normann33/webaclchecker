#!/bin/bash 

nohup python3 app.py < /dev/null > app.log 2>&1 &
