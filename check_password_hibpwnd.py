# -*- coding: utf-8 -*-
from haveibeenpwnd import check_password
import sys

def main():
    if check_password(raw_input().decode('utf8'))['count'] != 0 :
        print('BAD Password try again')
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
