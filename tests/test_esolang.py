from ctf_toolkit.osint_misc.esolang import brainfuck_eval


def test_brainfuck_eval():
    # Simple hello world / add test
    # Prints 'A' (65)
    src = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++."
    assert brainfuck_eval(src) == "A"


def test_brainfuck_brackets():
    # Loop multiplying 5 * 6 = 30
    src = "+++++[>++++++<-]>."
    out = brainfuck_eval(src)
    assert out == chr(30)
