#
# # H2o Plugin
#

import re
import idc
import idaapi


class Plugin(idaapi.plugin_t):

    help = "help"
    wanted_hotkey = ""
    comment = "comment"
    wanted_name = "plugin"
    flags = idaapi.PLUGIN_UNL

    def init(self):

        print "[+] H2o was loaded"
        print "[*] H2o by @shmuelyr"
        print "[*] github.com/shmuelyr"

        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass


class TableView(idaapi.Choose2):

    def __init__(self, title):

        idaapi.Choose2.__init__(self,
                                "SearchEx Table",
                                [
                                    ["Address", 13 | idaapi.Choose2.CHCOL_HEX],
                                    ["Instruction", 20 |
                                     idaapi.Choose2.CHCOL_PLAIN]
                                ]
                                )
        self.icon = 6
        self.items = list()
        self.refreshitems()
        self.select_list = list()

    def refreshitems(self):
        pass

    def OnSelectLine(self, n):
        try:
            addr = int(self.items[n][0], 16)
            idc.Jump(addr)
            print "[+] Jump to %s" % self.items[n][0]
        except:
            print "[-] Error while jumping"

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):
        return -1

    def OnClose(self):
        pass

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()


class AdvanceSearch(idaapi.Form):

    def __init__(self):

        self.invert = False
        self.tbl = TableView("SearchEx")
        idaapi.Form.__init__(self, r"""SearchEx
            <#Hint1#Function scope :{iScope}>
            <#Hint1#Expression     :{iExpr}>
            <#Hint1#Recursive level:{iRecu}><Regx:{rRegx}><line:{rLine}>{cRadio}>""",
                             {'iExpr': idaapi.Form.StringInput(),
                              'iScope': idaapi.Form.StringInput(),
                              'iRecu': idaapi.Form.StringInput(swidth=5, value=5),
                              'cRadio': idaapi.Form.RadGroupControl(("rRegx", "rLine"))
                              }
                             )

    def run(self, function_name, line, max_deep, mode):

        out = {}
        if mode == 0:  # regx
            out = self.DeepSearchWithRgx(function_name, line, max_deep)
        elif mode == 1:  # regular search
            out = self.DeepSearch(function_name, line, max_deep)
        if out:
            for addr, asm in out.iteritems():
                self.tbl.items.append([addr, asm])

            self.tbl.Show()
        else:
            print "there is no result"

    def DeepSearchWithRgx(self, function_name, regx, max_deep, current_deep=0):

        data = {}
        opcode_offset = 0
        function_start = idc.LocByName(function_name)
        function_end = idc.GetFunctionAttr(function_start, idc.FUNCATTR_END)
        while function_start + opcode_offset < function_end:

            opcode_index = function_start + opcode_offset
            dline = idc.GetDisasm(opcode_index)
            if idc.GetMnem(opcode_index) == "call":
                if current_deep >= max_deep:
                    return
                elif idc.GetOpnd(opcode_index, 0)[:4] == "sub_":
                    deep = self.DeepSearchWithRgx(
                        idc.GetOpnd(opcode_index, 0),
                        regx, max_deep, current_deep + 1)
                    if deep:
                        data.update(deep)

            tregx = re.match(regx, dline, 0)
            if tregx:
                data["%x" % opcode_index] = tregx.group()

            opcode_offset += idc.ItemSize(opcode_index)

        return data

    def DeepSearch(self, function_name, line, max_deep, current_deep=0):

        data = {}
        opcode_offset = 0
        function_start = idc.LocByName(function_name)
        function_end = idc.GetFunctionAttr(function_start, idc.FUNCATTR_END)
        while function_start + opcode_offset < function_end:

            opcode_index = function_start + opcode_offset
            dline = idc.GetDisasm(opcode_index)
            if idc.GetMnem(opcode_index) == "call":
                if current_deep >= max_deep:
                    return
                elif idc.GetOpnd(opcode_index, 0)[:4] == "sub_":
                    deep = self.DeepSearchWithRgx(
                        idc.GetOpnd(opcode_index, 0),
                        line, max_deep, current_deep + 1)
                    if deep:
                        data.update(deep)

            if dline == line:
                data["%x" % opcode_index] = dline

            opcode_offset += idc.ItemSize(opcode_index)

        return data


class AdvanceGo(idaapi.Form):

    def __init__(self):

        self.invert = False
        idaapi.Form.__init__(self, r"""GoEx
            <#Hint1#Expression:{iExpr}>""",
                             {'iExpr': idaapi.Form.StringInput()}
                             )

    def run(self, loc):

        loc = loc.replace("BASE", "0x%x" % idaapi.get_imagebase())
        loc = loc.replace("base", "0x%x" % idaapi.get_imagebase())
        try:
            location = eval(loc.replace("BASE", "0x%x" %
                                        idaapi.get_imagebase()))
        except:
            print """Error while parse your expresstion
            usage : <base> + <x>
            base/BASE = image base of module
            x = value (for hex used 0x prefix)
            """
            return
        print "GoEx : 0x%x" % location
        idc.Jump(location)


def init():

    idaapi.CompileLine('static Go() { RunPythonStatement("GoEx()"); }')
    idaapi.CompileLine('static GetRva() { RunPythonStatement("GetRVA()"); }')
    idaapi.CompileLine('static Search() { RunPythonStatement("SearchEx()"); }')

    idc.AddHotkey("Shift+G", 'Go')
    idc.AddHotkey("Shift+R", 'GetRva')
    idc.AddHotkey("Shift+S", 'Search')


def GoEx():

    form = AdvanceGo()
    form.Compile()

    ok = form.Execute()
    if ok:
        form.run(form.iExpr.value)
    form.Free()


def SearchEx():

    form = AdvanceSearch()
    form.Compile()

    ok = form.Execute()
    if ok:
        try:
            RecLvl = int(form.iRecu.value, 10)
        except:
            print "Enter valid Recursive level"
            form.Free()
            return
        form.run(form.iScope.value, form.iExpr.value, RecLvl, form.cRadio.value)
    form.Free()


def GetRVA():

    rva = idc.ScreenEA() - idaapi.get_imagebase()
    print "RVA of 0x%x is 0x%x" % (idc.ScreenEA(), rva)


def PLUGIN_ENTRY():

    init()
    return Plugin()
