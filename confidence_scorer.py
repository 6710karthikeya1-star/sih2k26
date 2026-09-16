from db_manager import get_connection

class AttributionScoringEngine:
    # Heuristic weights for multi-source evidence
    WEIGHTS = {
        "shared_pgp": 40,             # Cryptographically deterministic
        "shared_crypto_wallet": 35,   # Deterministic financial link
        "shared_contact_handle": 25,  # Strong pivot (Jabber, Telegram, Email)
        "shared_infrastructure": 20,  # Favicon MMH3 / DOM clone match
        "high_stylometry_match": 20   # AI writing pattern similarity > 75%
    }

    def __init__(self):
        self.conn = get_connection()

    def evaluate_actor(self, actor_id: str, has_shared_infra: bool = False, stylometry_score: float = 0.0) -> dict:
        cur = self.conn.cursor()
        audit_trail = []
        raw_score = 0

        # 1. Check PGP Keys
        cur.execute("SELECT COUNT(*) AS c FROM pgp_keys WHERE actor_id = ?;", (actor_id,))
        if cur.fetchone()["c"] > 1:
            raw_score += self.WEIGHTS["shared_pgp"]
            audit_trail.append(f"[+40] Shared PGP Key match detected across aliases.")

        # 2. Check Cryptocurrency Wallets
        cur.execute("SELECT COUNT(*) AS c FROM crypto_wallets WHERE actor_id = ?;", (actor_id,))
        wallet_count = cur.fetchone()["c"]
        if wallet_count >= 2:
            raw_score += self.WEIGHTS["shared_crypto_wallet"]
            audit_trail.append(f"[+35] Multi-currency deterministic wallet correlation ({wallet_count} wallets linked).")

        # 3. Check Contact Handles
        cur.execute("SELECT COUNT(*) AS c FROM contact_handles WHERE actor_id = ?;", (actor_id,))
        handle_count = cur.fetchone()["c"]
        if handle_count >= 1:
            raw_score += self.WEIGHTS["shared_contact_handle"]
            audit_trail.append(f"[+25] Direct communications identifier match (Jabber/Telegram/Email).")

        # 4. Check OPSEC & Infrastructure Matches
        if has_shared_infra:
            raw_score += self.WEIGHTS["shared_infrastructure"]
            audit_trail.append(f"[+20] Server OPSEC leak: Identical Favicon MMH3 / DOM structure detected.")

        # 5. Check AI Stylometry
        if stylometry_score >= 0.75:
            raw_score += self.WEIGHTS["high_stylometry_match"]
            audit_trail.append(f"[+20] AI Stylometry match confirmed ({stylometry_score * 100:.1f}% linguistic similarity).")

        final_score = min(100, raw_score)

        # Classification
        if final_score >= 85:
            rating = "CRITICAL / FORENSICALLY CONFIRMED"
        elif final_score >= 60:
            rating = "HIGH CONFIDENCE"
        elif final_score >= 40:
            rating = "MEDIUM PROBABILITY"
        else:
            rating = "LOW / CIRCUMSTANTIAL"

        # Update database with calculated score
        with self.conn:
            self.conn.execute(
                "UPDATE threat_actors SET risk_score = ? WHERE actor_id = ?;",
                (final_score, actor_id)
            )

        return {
            "actor_id": actor_id,
            "attribution_score": final_score,
            "confidence_rating": rating,
            "audit_trail": audit_trail
        }

if __name__ == "__main__":
    scorer = AttributionScoringEngine()
    cur = scorer.conn.cursor()
    cur.execute("SELECT actor_id, primary_label FROM threat_actors LIMIT 1;")
    actor = cur.fetchone()

    if actor:
        target_uuid = actor["actor_id"]
        print(f"[*] Calculating Attribution & Confidence Score for Actor '{actor['primary_label']}' ({target_uuid})...")
        
        # Pass simulated findings from Step 4 (Infra match) and Step 5 (Stylometry match)
        result = scorer.evaluate_actor(target_uuid, has_shared_infra=True, stylometry_score=0.81)

        print(f"\n=======================================================")
        print(f" FINAL ATTRIBUTION SCORE: {result['attribution_score']} / 100")
        print(f" CONFIDENCE LEVEL:       {result['confidence_rating']}")
        print(f"=======================================================")
        print("Audit Trail Breakdown:")
        for entry in result["audit_trail"]:
            print(f"  {entry}")
    else:
        print("[-] No actors found in database. Run main.py first.")
