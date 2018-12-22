from haveibeenpwnd import check_password
import sys

def main():
    if check_password(raw_input())['count'] != 0 :
        print('BAD Password try again')
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
