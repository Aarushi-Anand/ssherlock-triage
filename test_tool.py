from tool import score_ip,analyse_logs

def test_score_ip_malicious():
    log={"failures": 47,"success":True,"users_tried":{"root"}}
    result=score_ip(log,{"malicious":6},{"score":92,"reports":30})
    assert result["verdict"] == "MALICIOUS"

def test_score_ip_clean():
    log={"failures": 0,"success":False,"users_tried":set()}
    result=score_ip(log,None, None)
    assert result["verdict"] == "CLEAN"

def test_analyse_logs():
    result=analyse_logs("sample_log.log")
    assert result["9.9.9.9"]["failures"] == 5
    assert result["9.9.9.9"]["success"] is True