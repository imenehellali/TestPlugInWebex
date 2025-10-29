import argparse, requests, time, uuid, random

SERVER = 'http://localhost:5000'
E164_PREFIXES = ['+4930', '+4420', '+331', '+49151', '+1415']

def rand_e164():
    pref = random.choice(E164_PREFIXES)
    rest = ''.join(str(random.randint(0,9)) for _ in range(6))
    return pref + rest

def post_event(event, call_id=None, caller=None, transcript=''):
    if call_id is None: call_id = str(uuid.uuid4())
    body = {'event': event, 'call_id': call_id, 'caller': caller or rand_e164(), 'transcript': transcript}
    r = requests.post(SERVER + '/simulate', json=body, timeout=5)
    print(event, r.status_code, r.text)
    return call_id

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--caller', help='E.164 number like +49301234567')
    ap.add_argument('--random', action='store_true', help='use random caller each run')
    ap.add_argument('--rate', type=int, default=1, help='calls per minute in load mode')
    ap.add_argument('--load', action='store_true', help='continuous random calls')
    args = ap.parse_args()

    if args.load:
        period = 60/max(args.rate,1)
        while True:
            cid = post_event('started', caller=(None if args.random else args.caller))
            time.sleep(0.5)
            post_event('connected', call_id=cid, caller=(None if args.random else args.caller),
                       transcript='AI→User handoff; CID={}'.format(cid))
            time.sleep(1.5)
            post_event('ended', call_id=cid, caller=(None if args.random else args.caller))
            time.sleep(period)
    else:
        cid = post_event('started', caller=(None if args.random else args.caller))
        time.sleep(1.0)
        post_event('connected', call_id=cid, caller=(None if args.random else args.caller),
                   transcript='Caller connected; CID={}'.format(cid))
        time.sleep(1.0)
        post_event('ended', call_id=cid, caller=(None if args.random else args.caller))
