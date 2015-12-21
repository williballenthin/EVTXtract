
Purpose
-------
EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.


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
5. Reconstruct records by reusing old templates with recovered substitutions


Usage
-----

The EVTXtract tools are a set of pure Python scripts.
To extract and recover records, users must call a sequence of the scripts.
One can easily build a more intuitive user interface on top of these lower level scripts; however, this UI will not be as simple and flexibile.

## Dependencies:
EVTXtract depends on the following pure Python modules that are easily installable using `pip` or `easy_install`:

  - [python-evtx](http://www.williballenthin.com/evtx/)
  - [progressbar](http://code.google.com/p/python-progressbar/)

## Scripts
Each of the following scripts accepts the same positional arguments:

  - [binary file] : path to the binary input file, which may be an existing EVTX file, or some time of raw image (DD, memory, etc.).
  - [project name] : (optional) a single word or identifier that describes the record recovery effort. This is used to create the state file that tracks recovered records. Defaults to "default".
  - [template project name] : (optional) a single word or identifier that describes the template recovery effort. This is used to create the template database file. Defaults to "default_db", or "[project_name]_db" if [project name] is specified.


### find_evtx_chunks.py
#### Summary
`find_evtx_chunks.py` scans the input file and identifies potential EVTX chunks.
For each chunk, it attempts to verify the chunk data using a checksum, and saves the positions of the valid chunks.
Because of the checksum, subsequent scripts can assume the valid chunks are complete, regardless of where they were found.
This script saves the valid chunk locations in the project file.

#### Example
    Git/EVTXtract $ python find_evtx_chunks.py unallocated.bin ACME_system1 ACME_system1 --progress
    Progress: 1118208 of 1118208 100% [============================================================================================] Time: 0:00:00
    # Found 9 valid chunks.


### extract_valid_evtx_records_and_templates.py
#### Summary
`extract_valid_evtx_records_and_templates.py` uses the locations of valid EVTX chunks from the state file to extract verified data.
It will parse out all of the valid EVTX records and save them in the project file.
These records can be considered correct because their chunk's checksum was previously verified.
It also extracts a representation of each encountered template into the template database file.
These templates are subsequently used to reconstruct lost records.
Once this script has completed, users can review all the valid EVTX records using the script `show_valid_records.py`.
This script saves the valid records in the project file, and the recovered templates in the template database file.
Users can run this script against complete EVTX files to extract known templates.
By reusing the same template database file, and varying the input file, users can collect templates from many sources.

#### Example
    Git/EVTXtract $ python extract_valid_evtx_records_and_templates.py unallocated.bin ACME_system1 ACME_system1 --progress
    Progress: 8 of 8 100% [======================================================================] Time: 0:00:05
    # Found 29 new templates.
    # Found 847 new valid records.


### find_evtx_records.py
#### Summary
`find_evtx_records.py` scans the input file and identifies potential EVTX records.
These records will be "lost" records, that is, records that do not fall within a verified EVTX chunk.
The script uses a heuristic to identify structures that appear to be EVTX records; however, it may be fooled in unusual, and uncommon, circumstances.
This script saves the potential record locations in the project file.
Subsequent scripts extract these fragments and attempt to reconstruct them using known templates.

#### Example
    Git/EVTXtract $ python find_evtx_records.py unallocated.bin ACME_system1 ACME_system1 --progress
    Progress: 46144 of 46144 100% [==============================================================] Time: 0:00:00
    # Found 65 potential EVTX records.

### extract_lost_evtx_records.py
#### Summary
`extract_lost_evtx_records.py` uses the locations of "lost" records from the state file to extract these record's substitution data.
It parses out record header data, such as record number, as well as the substitution array.
This script saves the extracted record data in the project file.
Subsequent scripts will combine the substitution data extracted from "lost" records with the template database to reconstruct complete entries.

#### Example
    Git/EVTXtract $ python extract_lost_evtx_records.py unallocated.bin ACME_system1 ACME_system1 --progress
    Progress: 129 of 129 100% [==================================================================] Time: 0:00:00
    # Extracted 130 records.
    # Failed to extract 0 potential records.


### reconstruct_lost_records.py
#### Summary
`reconstruct_lost_records.py` takes the data from "lost" records saved in the state file and tries to reconstruct the original entries using the template database.
It uses the signature of the subtitution array and EID to make a best guess as to which template to apply to a subsitution array.
A record can be successfully reconstructed if the signature of its substitutions exactly match a template's signature, and there is no ambiguity (more than one template has the same signature, a "template conflict").
This script is unable to reconstruct records whose substitution array have a previously unencountered signature, or match more than one potential template.
This script saves the reconstructed and unreconstructed records in the project file.
The reconstructed record will contain the XML of a complete entry, while an unreconstructed record will retain the raw substitution array and an the error.

#### Example
    Git/EVTXtract $ python reconstruct_lost_records.py unallocated.bin ACME_system1 ACME_system1 --progress
    Progress: 130 of 130 100% [==================================================================] Time: 0:00:00
    # Reconstructed 130 records.
    # Failed to reconstruct 0 records.

### show_valid_records.py
#### Summary
`show_valid_records.py` prints to standard output the XML entries for the valid and verified records recovered by `extract_valid_evtx_records_and_templates.py`.
This script does not modify the project or template database files.

#### Example
    Git/EVTXtract $ python show_valid_records.py unallocated.bin ACME_system1 ACME_system1 | head
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-a5ba-3e3b0328c30d"></Provider>
    <EventID Qualifiers="">4608</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12288</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2012-08-30 05:50:37.361267"></TimeCreated>
    <EventRecordID>1</EventRecordID>
    <Correlation ActivityID="" RelatedActivityID=""></Correlation>
    ...

### show_reconstructed_records.py
#### Summary
`show_reconstructed_records.py` prints to standard output the XML entries reconstructed by `reconstruct_lost_records.py`.
This script does not modify the project or template database files.

#### Example
    Git/EVTXtract $ python show_reconstructed_records.py unallocated.bin ACME_system1 ACME_system1 | head
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft\-Windows\-Security\-Auditing" Guid="0001010f\-010c\-ca6d\-72c7\-260200000000"></Provider>
    <EventID Qualifiers="None">4608</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12288</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2012\-08\-30T05\:50\:37\.361267Z"></TimeCreated>
    <EventRecordID>1</EventRecordID>
    <Correlation ActivityID="None" RelatedActivityID="None"></Correlation>
    ...


### show_unreconstructed_records.py
#### Summary
`show_unreconstructed_records.py` prints to standard output the metadata and subsitution array for records that were not able to be reconstructed by `reconstruct_lost_records.py`.
This script does not modify the project or template database files.

#### Example
    Git/EVTXtract $ python show_unreconstructed_records.py unallocated.bin ACME_system1 ACME_system1 | head
    UNRECONSTRUCTED RECORD
    Offset: 512
    Reason: No loaded templates with EID: 4608
    Substitutions:
      Substitution: UnsignedByte  0
      Substitution: UnsignedByte  0
      Substitution: UnsignedWord  12288
      Substitution: UnsignedWord  4608
      Substitution: Null  None
      Substitution: Hex64  0x8020000000000000


## Wizard
EVTXtract is provided as a set of lower level scripts so they can be recombined in different ways depending on the situation.
For example, you may be able to process and extract files from a disk image (which will help EVTXtract do its magic), but not be able to do much relevant extra processing on a memory image.
The following describes a few common cases to help you get familiar with the EVTXtract workflow.

0. Call the project: `$project`, vinary evidence file: `$evidence`, and have `identifier()` be some function (can even take place in your brain!) that takes a filename and gives a nice readable name (perhaps, `basename` with whitespace stripped out).
1. Can you get any EVTX files related to the evidence? call these `$real_evtxs`.
2. Is the evidence an image, and can you and/or do you want to process just unallocated space? call this `$unalloc`.

If 1 & 2 are true, then we can extract the legitimate templates from the existing EVTX files, and focus our recovery on the unallocated space. This is the best case.

    for each $real_evtx in $real_evtxs:
      python find_evtx_chunks.py $real_evtx identifier($real_evtx) $project
      python extract_valid_evtx_records_and_templates.py $real_evtx identifier($real_evtx) $project
    python find_evtx_chunks.py $evidence $project $project
    python extract_valid_evtx_records_and_templates.py $unalloc $project
    python find_evtx_records.py $unalloc $project $project
    python extract_lost_evtx_records.py $unalloc $project $project
    python reconstruct_lost_records.py $unalloc $project $project
    python show_reconstructed_records.py $unalloc $project $project

If 1 is true, 2 is false, then we can extract the legitimate templates from the existing EVTX files, but we might double-process entries (which is fine, but takes longer).

    for each $real_evtx in $real_evtxs:
      python find_evtx_chunks.py $real_evtx identifier($real_evtx) $project
      python extract_valid_evtx_records_and_templates.py $real_evtx identifier($real_evtx) $project
    python find_evtx_chunks.py $evidence $project $project
    python extract_valid_evtx_records_and_templates.py $evidence $project $project
    python find_evtx_records.py $evidence $project $project
    python extract_lost_evtx_records.py $evidence $project $project
    python reconstruct_lost_records.py $evidence $project $project
    python show_reconstructed_records.py $unalloc $project $project

Otherwise, we can discover everything we can using no a priori knowledge of the evidence.

    python find_evtx_chunks.py $evidence $project $project
    python extract_valid_evtx_records_and_templates.py $evidence $project $project
    python find_evtx_records.py $evidence $project $project
    python extract_lost_evtx_records.py $evidence $project $project
    python reconstruct_lost_records.py $evidence $project $project
    python show_reconstructed_records.py $evidence $project $project


Developer Stuff
---------------

### JSON format
EVTXtract stores the current state of each project in a pair of JSON encoded files.
The following sections describe the schema for the JSON objects.

#### State file
    {
      version: int
      generator: str

      // metadata, for confirmation subsequent calls use the same input file
      input_file: {
        size: int
        md5: str    // hex encoded md5sum of the first 0x100000 bytes of the input file
      }

      valid_chunk_offsets: [int, int, ...]
      potential_record_offsets: [int, int, ...]
      valid_records: [
        {
          offset: int
          eid: int
          xml: str
        },
        ...
      }
      lost_records: [
        {
          offset: int
          substitutions: [(str, str), (str, str), ...]
        },
        ...
      ]
      reconstructed_records: [
        {
          offset: int
          eid: int
          xml: str
        },
        ...
      ]
      unreconstructed_records: [
        {
          offset: int
          substitutions: [(str, str), (str, str), ...]
          reason: str
        },
        ...
      ]
    }

#### Template File
    {
      version: int
      generator: str

      templates: {
        (int)eid: [
          {
            eid: int,
            id: str,
            xml: str,
          },
          ...
        ]
      }
    }


### TODO
1. DONE fix valid_record xml
2. DONE fix bug parsing chunks and records for valid records/templates
3. DONE ensure templates are not duplicated in the database
4. DONE Figure out what happens with multiple runs on different files
     --> they must match, or the offsets will get screwed up
     --> therefore, the bug is to warn if the files differ, or if data already exists
5. DONE Logging issue
    Git/recover-evtx - [json-db\u25cf] \u00bb python extract_valid_evtx_records_and_templates.py tests/working-private/chunk_fragment/chunk_fragment.evtx
      No handlers could be found for logger "extract_records"
6. DONE Move argparser config to common area
7. figure out idempotency for state, related: #4
     --> this should probably be up to the user, or it gets very confusing.
     --> could perhaps add flags to the state file describing what tools have been run
8. consider GZIPing the state and database files
9. DONE write dumping scripts
10. DONE implement .get_template
11. DONE figure out where IDs should be used --> nowhere
12. DONE move things out of main
13. NO consider writing a Q&A/wizard style interface
14. DONE develop flowchart describing usage
15. DONE for state/db file, on error, should the existing state be written out best-effort?
16. DONE Template.get_id is broken, only returns EID
17. DONE if project name specified, update the templatedb default
18. DONE templatedb filename should always end in _db.json
19. NO extract constraints in template DB for easy matching
20. DONE add status output so the user knows that something happened. Use print() for this, not logging
21. DONE make substitution object/list things consistent. 2- or 3-tuples?
22. DONE nested template indices are incorrect. seems to be a string concat somewhere
23. rewrite tests
24. need a means to identify template conflicts and resolve them
25. remove old scripts (merge template files, validate)
26. check the checksumming
27. handle arbitrary binary data

Blockers: 23
