from ctf_toolkit.osint_misc.esolang import brainfuck_eval, ook_eval, ook_to_brainfuck


def test_brainfuck_eval():
    src = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++."
    assert brainfuck_eval(src) == "A"


def test_brainfuck_brackets():
    src = "+++++[>++++++<-]>."
    out = brainfuck_eval(src)
    assert out == chr(30)


def test_ook_eval():
    # Ook code printing 'A' (65 pluses + dot)
    # Ook. Ook. is +
    # Ook! Ook. is .
    src = "Ook. Ook. " * 65 + "Ook! Ook."
    assert ook_eval(src) == "A"
