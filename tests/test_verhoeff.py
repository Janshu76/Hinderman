from detectors.verhoeff import is_valid, verhoeff_check_digit, verhoeff_valid


def test_is_valid_is_the_same_function_as_verhoeff_valid():
    assert is_valid is verhoeff_valid


def test_known_valid_numbers():
    assert is_valid("2363")
    assert is_valid("123451")
    assert is_valid("0")


def test_known_check_digits():
    assert verhoeff_check_digit("236") == "3"
    assert verhoeff_check_digit("12345") == "1"


def test_check_digit_makes_any_number_valid():
    for base in ("1", "99", "2345", "234567890123", "000000", "9876543210987"):
        assert is_valid(base + verhoeff_check_digit(base)), base


def test_every_single_digit_typo_is_caught():
    number = "2345678901" + verhoeff_check_digit("2345678901")
    for pos in range(len(number)):
        for wrong in "0123456789":
            if wrong == number[pos]:
                continue
            typo = number[:pos] + wrong + number[pos + 1:]
            assert not is_valid(typo), (pos, wrong)


def test_every_adjacent_swap_is_caught():
    number = "2345678901" + verhoeff_check_digit("2345678901")
    for pos in range(len(number) - 1):
        if number[pos] == number[pos + 1]:
            continue
        swapped = number[:pos] + number[pos + 1] + number[pos] + number[pos + 2:]
        assert not is_valid(swapped), pos


def test_wrong_check_digit_rejected():
    right = verhoeff_check_digit("236")
    for wrong in "0123456789":
        if wrong != right:
            assert not is_valid("236" + wrong)


def test_non_digit_and_empty_input_rejected():
    assert not is_valid("")
    assert not is_valid("23a3")
    assert not is_valid("2363 ")
    assert not is_valid("236-3")
