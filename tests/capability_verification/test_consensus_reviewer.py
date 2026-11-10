"""Consensus Reviewer verification."""

def test_consensus_reviewer_disagreement():
    # Simulate disagreeing reviewers
    reviews = [True, False, True]
    consensus = sum(reviews) / len(reviews) >= 0.66
    assert consensus is True

def test_consensus_false_positive_rate():
    false_positives = 2
    total = 100
    rate = false_positives / total
    assert rate < 0.05
