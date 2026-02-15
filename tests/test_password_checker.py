import password_checker as pc


def test_empty_password_score_zero():
    score, findings, suggestions, entropy = pc.calculate_score_and_suggestions("")
    assert score == 0
    assert any("empty" in f.lower() for f in findings)


def test_dictionary_hits_password():
    words = {"password", "admin", "welcome"}
    hits = pc.find_dictionary_hits("Password1234!", words)
    assert "password" in hits


def test_dictionary_hits_leetspeak():
    words = {"password", "admin", "welcome"}
    hits = pc.find_dictionary_hits("P@ssw0rd123!", words)
    assert "password" in hits


def test_sequence_penalty_applies():
    score_seq, *_ = pc.calculate_score_and_suggestions("Abcd1234!!")
    score_no_seq, *_ = pc.calculate_score_and_suggestions("Axcd1294!!")
    assert score_seq < score_no_seq


def test_repeat_penalty_applies():
    score_rep, *_ = pc.calculate_score_and_suggestions("AAAA1111!!!!")
    score_no_rep, *_ = pc.calculate_score_and_suggestions("AAAB1112!!!?")
    assert score_rep < score_no_rep
