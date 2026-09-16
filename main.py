from entity_extractor import extract_entities
from resolution_pipeline import EntityResolutionEngine

DREAD_HTML = '''
<html>
  <p>Vendor: DreadOps</p>
  <p>Reach me on Jabber: phantom_ops@exploit.im</p>
  <p>XMR Address: 888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkFxbANsAnJYPbb3iQ1YBRk1UXCDRSiKc9bkMyNVZnnC5Bjpps557xKqAb7</p>
</html>
'''

EXPLOIT_HTML = '''
<html>
  <p>Alias: ApexBreach</p>
  <p>Jabber: phantom_ops@exploit.im</p>
  <p>BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
</html>
'''

if __name__ == "__main__":
    engine = EntityResolutionEngine()

    print("[*] Ingesting Dread Forum post...")
    d1 = extract_entities(DREAD_HTML, "http://dreadmarket.onion/thread/1")
    a1 = engine.process_and_ingest(d1, "DreadOps", "Dread")
    print(f"    -> Resolved Actor ID: {a1}")

    print("[*] Ingesting Exploit Forum post...")
    d2 = extract_entities(EXPLOIT_HTML, "http://exploitmarket.onion/thread/2")
    a2 = engine.process_and_ingest(d2, "ApexBreach", "Exploit")
    print(f"    -> Resolved Actor ID: {a2}")

    if a1 == a2:
        print("\n[SUCCESS] 'DreadOps' and 'ApexBreach' resolved to the SAME Actor UUID!")
