def score_ip(results,vt,ad):
    score=0
    reasons=[]
    if ad:
        if ad["score"]>75:
            score+=40
            reasons.append(f"AbuseIPdb score {ad['score']}")

        elif ad["score"]>25:
            score+=20
            reasons.append(f"AbuseIPdb score {ad['score']}")

    if vt and vt["malicious"] >= 5:
            score+=30
            reasons.append(f"VirusTotal: {vt['malicious']} engines flagged")

    if results["failures"] >= 5:
        score+=20
        reasons.append(f"{results['failures']} failed logins")
        if results["success"]:
            score+=30
            reasons.append("Login succeeded after failures")
            
    score=min(score,100)

    verdict = ""
    if score >= 70:
        verdict="MALICIOUS"
    elif score>=30:
        verdict="SUSPICIOUS"
    else:
        verdict="CLEAN"
    
    return {"verdict": verdict, "score": score, "reasons": reasons}

