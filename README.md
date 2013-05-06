
Background
----------

EVTX records are XML fragments encoded using a Microsoft-specific binary XML representation.
Despite the convenient format, it is not easy to recover EVTX event log records from a corrupted file or unallocated space.
This is because the complete representation of a record often depends on other records found nearby.
The event log service recognizes similarities among records and refactors commonalities into "templates".
A template is a fixed structure with placeholders that reserve space for variable content.
The on-disk event log record structure is a reference to a template, and a list of substitutions (the variable content the replaces a placeholder in a template).
To decode a record into XML, the event log service resolves the template and replaces its placeholders with the entries of the substitution array.
Therefore, template corruption renders many records unrecoverable within the local 64KB "chunk".
However, the substitution array for the remaining records may still be intact.
If so, it may be possible to produce XML fragments that match the original records if the damaged template can be reconstructed.
For many common events, such as process creation or account logon, empirical testing demonstrates the relevant templates remain mostly constant.
In these cases, recovering event log records boils down to identifying appropriate templates found in other EVTX chunks.


Algorithm
---------

1. Scan for chunk signatures ("ElfChnk")
   - check header for sane values (0x80 <= size <= 0x200)
   - verify checksums (header, data)
2. Extract records from valid chunks found in (1)
3. Extract templates from valid chunks found in (1)
4. Scan for record signatures
   - check header for sane values
   - extract timestamp
   - attempt to parse substitutions
   - attempt to decode substitutions into EID, other fields



