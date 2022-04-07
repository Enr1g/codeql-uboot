import cpp

class MacroExpr extends Expr {
    MacroExpr() {
        exists(
            MacroInvocation mi |
            mi.getMacroName() in ["ntohs", "ntohl", "ntohll"] and
            this = mi.getExpr()
        )
    }
}

from MacroExpr me
select me
