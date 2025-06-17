import psutil

def main():
    for proc in psutil.process_iter(['pid','name','username']):
        print(f"{proc.info['pid']:>5}  {proc.info['name']:<25}  {proc.info['username']}")

if __name__ == '__main__':
    main()
