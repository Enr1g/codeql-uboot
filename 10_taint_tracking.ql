import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class MacroExpr extends Expr {
    MacroExpr() {
        exists(
            MacroInvocation mi |
            mi.getMacroName() in ["ntohs", "ntohl", "ntohll"] and
            this = mi.getExpr()
        )
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "network_to_memory"}

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof MacroExpr
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(
            FunctionCall fc|
            fc.getArgument(2) = sink.asExpr() and
            fc.getTarget().getName() = "memcpy"
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select source, sink, "Network byte swap flows to memcpy"
