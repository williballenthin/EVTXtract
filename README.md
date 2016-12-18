
Purpose
-------
EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.

Quick Run
---------

Install EVTXtract via `pip`:

    pip install evtxtract

Now the tool is ready to go!

    C:/Python27/Scripts/evtxtract.exe   Z:/evidence/1/image.dd   >   Z:/work/1/evtx.xml


Quicker Run
-----------

Download standalone executable nightly builds of EVTXtract here:

  - [Linux](https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/evtxtract)
  - [MacOS](https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/osx/dist/evtxtract)

Then you can do:

    ./evtxtract    /path/to/evidence    >   /path/to/output.xml


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

The EVTXtract is a pure Python script.
This means it easily runs on Windows, Linux, and MacOS.
Simply invoke the script, providing the path to a binary image, and EVTXtract writes its results to the standard out stream.
The binary file can be any data: a raw image, memory dump, etc.

Example command line:

    C:/Python27/Scripts/evtxtract.exe   Z:/evidence/1/image.dd   >   Z:/work/1/evtx.xml

Below are some example results from the above command.
It shows two records: a complete and incomplete record.
The first record is completely reconstructed,
  and is formatted just like it would be in event viewer.
However, EVTXtract was unable to complete reconstruct the second record,
 since some critical template data was missing.
So, its been formatted with as much data as was recovered.
EVTXtract uses a schema that allows you to continue processing despite incomplete data.

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-PrintService" Guid="{747ef6fd-e535-4d16-b510-42c90f6873a1}"></Provider>
            <EventID Qualifiers="">823</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>49</Task>
            <Opcode>11</Opcode>
            <Keywords>0x80000000000200</Keywords>
            <TimeCreated SystemTime="2013-03-23 02:05:57.848455"></TimeCreated>
            <EventRecordID>1</EventRecordID>
            <Correlation ActivityID="" RelatedActivityID=""></Correlation>
            <Execution ProcessID="1204" ThreadID="1208"></Execution>
            <Channel>Microsoft-Windows-PrintService/Admin</Channel>
            <Computer>JOSHUA</Computer>
            <Security UserID="S-1-5-21-3454551831-629247693-1078506759-1000"></Security>
        </System>
        <UserData>
            <ChangingDefaultPrinter xmlns:auto-ns3="http://schemas.microsoft.com/win/2004/08/events" xmlns="http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events">
                <DefaultPrinterSelectedBySpooler>1</DefaultPrinterSelectedBySpooler>
                <OldDefaultPrinter></OldDefaultPrinter>
                <NewDefaultPrinter>Microsoft XPS Document Writer,winspool,Ne00:</NewDefaultPrinter>
                <Status>0x000000</Status>
                <Module>spoolsv.exe</Module>
            </ChangingDefaultPrinter>
        </UserData>
    </Event>

    ...

    <Record>
    <Offset>0x317198</Offset>
    <EventID>1531</EventID>
    <Substitutions>
      <Substitution index="0">
        <Type>4</Type>
        <Value>4</Value>
      </Substitution>
      <Substitution index="1">
        <Type>4</Type>
        <Value>0</Value>
      </Substitution>
      <Substitution index="2">
        <Type>6</Type>
        <Value>0</Value>
      </Substitution>
      <Substitution index="3">
        <Type>6</Type>
        <Value>1531</Value>
      </Substitution>
      <Substitution index="4">
        <Type>0</Type>
        <Value></Value>
      </Substitution>
      <Substitution index="5">
        <Type>21</Type>
        <Value>0x8000000000000000</Value>
      </Substitution>
      <Substitution index="6">
        <Type>17</Type>
        <Value>2013-03-23 02:02:35.679552</Value>
      </Substitution>
      <Substitution index="7">
        <Type>0</Type>
        <Value></Value>
      </Substitution>
      <Substitution index="8">
        <Type>8</Type>
        <Value>928</Value>
      </Substitution>
      <Substitution index="9">
        <Type>8</Type>
        <Value>1040</Value>
      </Substitution>
      <Substitution index="10">
        <Type>10</Type>
        <Value>132</Value>
      </Substitution>
      <Substitution index="11">
        <Type>4</Type>
        <Value>0</Value>
      </Substitution>
      <Substitution index="12">
        <Type>19</Type>
        <Value>S-1-5-18</Value>
      </Substitution>
      <Substitution index="13">
        <Type>0</Type>
        <Value></Value>
      </Substitution>
      <Substitution index="14">
        <Type>1</Type>
        <Value>Microsoft-Windows-User Profiles Service</Value>
      </Substitution>
      <Substitution index="15">
        <Type>15</Type>
        <Value>0001010f-010c-77e3-bf2f-3ef300001200</Value>
      </Substitution>
      <Substitution index="16">
        <Type>1</Type>
        <Value>Application</Value>
      </Substitution>
    </Substitutions>
    </Record>
