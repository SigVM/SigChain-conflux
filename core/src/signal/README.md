# Signals and Slots Implementation on Conflux
This directory hosts the bulk of the source code that implements signals and slots. Small parts of the original conflux source tree are also changed in order to support this feature. The purpose of this document is to outline how signals and slots are implemented and to keep track of the changes to the original source tree.

### Signals Implementation
Signals are described as a struct containing an id, owner, and argument count. Upon the creation of a new signal, a unique id is generated using the owner address and the last element of the sig_list in the owner account. This ensures that a unique id is generated everytime a signal is created.

### Changes to Conflux Source Tree
1. core/src/evm/: Added CREATESIG, BINDSIG and EMITSIG to instructions.rs and interpreter/mod.rs. 
2. core/src/state/: A few fields need to be added to OverlayAccount to keep track of the mapping between signals and slots as well as upcoming slot transactions. 
    * slot_tx_queue: queue that holds all the slot transactions that need to be serviced.
    * sig_list: list of signal id's that this account owns.
    * sig_cache: cache that maps signals to their respective slots.
    * sig_changes: new signal slot relations that need to be committed to storage.
Each signal gets its own storage key derived from the owner account address and its unique id. This key will be used to access the mapping to its relevant slots. 
Beyond adding to OverlayAccount, new functions need to be added to support the new state changes needed by the new opcodes.
3. core/src/vm/: The trait ```Context``` needs to be extended to support the new state changes. 
4. core/src/executive/: The changes in the context trait need to be implemented in in context.rs.
5. core/src/vm/: We probably want to change env.rs so that it includes something about the previous blocks average gas price. This field can then be used to calculate the gasprice of slot transactions. How do we deal with floating point numbers?