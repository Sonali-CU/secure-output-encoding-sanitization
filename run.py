import argparse
from app import create_app

def main():
    parser = argparse.ArgumentParser(description="Secure Output Encoding & Input Sanitization Suite")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    args = parser.parse_args()

    app = create_app()

    print("=" * 70)
    print("🛡️  Secure Output Encoding & Input Sanitization Suite")
    print("   Author: Sonali Gupta (CU23BCA0060A) &middot; Chanakya University")
    print(f"   Server listening at: http://{args.host}:{args.port}")
    print("   All 10 defensive encoding and sanitization modules active.")
    print("=" * 70)

    app.run(host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    main()
