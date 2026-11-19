---------------------------- MODULE ProvenanceGate ----------------------------
(***************************************************************************)
(* TLA+ counterpart of model M1 in model_check.py.                         *)
(* STATUS: NOT EXECUTED. TLC could not be obtained in the revision         *)
(* environment. The bounded checks reported in the paper were run with the *)
(* Python explicit-state checker (model_check.py). Run this spec with      *)
(*   java -cp tla2tools.jar tlc2.TLC -config ProvenanceGate.cfg ProvenanceGate *)
(* to obtain an independent check.                                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS N, CheckSeq, CheckSig, CheckRev, AllowKeyCompromise

Msg == [seq: 1..N, pl: {"g","b"}, ep: 0..1, sv: BOOLEAN, au: BOOLEAN]

VARIABLES nxt, ch, kc, rev, ep, last, acc

vars == <<nxt, ch, kc, rev, ep, last, acc>>

Init == nxt = 1 /\ ch = {} /\ kc = FALSE /\ rev = {} /\ ep = 0 /\ last = 0 /\ acc = <<>>

Sign == nxt <= N /\ ch' = ch \cup {[seq |-> nxt, pl |-> "g", ep |-> ep, sv |-> TRUE, au |-> TRUE]}
        /\ nxt' = nxt + 1 /\ UNCHANGED <<kc, rev, ep, last, acc>>

Tamper(m) == m.pl = "g" /\ ch' = (ch \ {m}) \cup {[m EXCEPT !.pl = "b", !.sv = (kc /\ m.ep = ep), !.au = FALSE]}
             /\ UNCHANGED <<nxt, kc, rev, ep, last, acc>>

Drop(m) == ch' = ch \ {m} /\ UNCHANGED <<nxt, kc, rev, ep, last, acc>>

Ok(m) == /\ (CheckSig => m.sv)
         /\ (CheckRev => m.ep \notin rev)
         /\ (CheckSeq => m.seq = last + 1)

Accept(m) == Ok(m) /\ acc' = Append(acc, m) /\ last' = IF m.seq > last THEN m.seq ELSE last
             /\ UNCHANGED <<nxt, ch, kc, rev, ep>>

Compromise == AllowKeyCompromise /\ ~kc /\ kc' = TRUE /\ UNCHANGED <<nxt, ch, rev, ep, last, acc>>

Inject(s) == kc /\ ch' = ch \cup {[seq |-> s, pl |-> "b", ep |-> ep, sv |-> TRUE, au |-> FALSE]}
             /\ UNCHANGED <<nxt, kc, rev, ep, last, acc>>

RevokeRekey == kc /\ ep = 0 /\ rev' = rev \cup {ep} /\ ep' = ep + 1 /\ kc' = FALSE
               /\ UNCHANGED <<nxt, ch, last, acc>>

Next == \/ Sign \/ Compromise \/ RevokeRekey
        \/ \E m \in ch : Tamper(m) \/ Drop(m) \/ Accept(m)
        \/ \E s \in 1..N : Inject(s)

Spec == Init /\ [][Next]_vars

\* Invariants
Integrity  == \A i \in 1..Len(acc) : acc[i].au
NoReplay   == \A i, j \in 1..Len(acc) : i # j => acc[i].seq # acc[j].seq
InOrder    == \A i \in 1..(Len(acc)-1) : acc[i].seq < acc[i+1].seq
=============================================================================
