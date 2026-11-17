from candix.agent.review import Review, ReviewBoard, block_release, guidelines


def finding(**overrides):
    payload = {"id": "f1", "title": "Reflected XSS", "severity": "high", "category": "xss", "url": "http://a/s?q=1", "parameter": "q"}
    payload.update(overrides)
    return payload


def test_review_items_from_knowledge():
    review = Review.forget(finding())
    assert review.status == "pending"
    assert len(review.items) >= 4
    assert any("verification step" in item.text for item in review.items)
    assert guidelines({"category": "sqli"})


def test_review_checklist_and_approval():
    review = Review.forget(finding())
    for index in range(len(review.items)):
        review.check(index)
    assert review.progress == 1.0
    review.approve("ana")
    assert review.status == "approved"


def test_review_rejects_incomplete_approval():
    review = Review.forget(finding())
    try:
        review.approve("ana")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    review.reject("ana", "not reproducible")
    assert review.comments == ["not reproducible"]
    assert "rejected" in review.markdown()


def test_board_seed_and_summary(tmp_path):
    board = ReviewBoard()
    assert board.seed([finding(), finding(id="f2", title="SQLi", category="sqli", url="http://a/l", parameter="u")]) == 2
    assert board.seed([finding()]) == 0
    assert len(board.pending()) == 2
    ok, reason = block_release(board)
    assert not ok and "under review" in reason
    assert board.approve_all("ana") == 2
    assert block_release(board)[0]
    assert board.summary()["approved_ratio"] == 1.0


def test_board_persistence_and_assignment(tmp_path):
    board = ReviewBoard()
    board.seed([finding()])
    assert board.assign("luis") == 1
    path = board.save(tmp_path / "review.json")
    loaded = ReviewBoard.load(path)
    assert loaded.get("f1").reviewer == "luis"
    assert "## Finding review" in loaded.markdown()
    assert ReviewBoard.load(tmp_path / "missing.json").reviews == {}
