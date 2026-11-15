
import detector


def test_detection_rules():
    rules = detector.RULES

    tests = [
        (("System", 7040), True),
        (("Security", 1102), True),
        (("System", 1102), False),
        (("Security", 7040), False),
    ]

    passed = 0

    print("\n================================")
    print("     SENTINEL X AUTO TEST")
    print("================================")

    for event_key, expected in tests:
        result = event_key in rules
        status = "PASS" if result == expected else "FAIL"

        print(f"{event_key[0]} Event {event_key[1]}: {status}")

        if status == "PASS":
            passed += 1

    print("--------------------------------")
    print(f"Total test : {len(tests)}")
    print(f"Passed     : {passed}")
    print(f"Failed     : {len(tests) - passed}")

    print("--------------------------------")
    print("STATUS:", "SUCCESS" if passed == len(tests) else "FAILED")
    print("================================")


if __name__ == "__main__":
    test_detection_rules()
