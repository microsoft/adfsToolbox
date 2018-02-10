# Pester Tests for AdfsEventsModule

## Pester Overview

This project includes a set of [Pester](https://github.com/pester/Pester) tests to ensure the basic functionality of the AdfsEventsModule script. 

To run the tests, you must have Pester version 4.x or higher installed on the machine you will run ```Get-ADFSEvents``` from. 
For more information on installing Pester, see their [installation instructions](https://github.com/pester/Pester/wiki/Installation-and-Update). 

Once Pester is installed, you can copy the test file and script to the same location, and run the following: 

    cd <directory containing tests and script>
    Invoke-Pester -Script .\Test.AdfsEventsModule.ps1

## Side Effects 

The testing module will create a Relying Party Trust on your machine, which will be used for generating request logs. 
You should manually remove the Relying Party when you have completed testing. 

## Test Matrix 


| CorrelationID or All | CreateAnalysisData | FromFile | Server Count | ByTime| Scenario Num | Code Coverage | 
| --- | --- | --- | --- | --- | --- | --- |
| All | No | No | 1 | No | 00000 | Covered |
| All | No | No | 1 | Yes | 00001 | Covered |
| All | No | No | 2 | No | 00010 | Multinode Not in scope |
| All | No | No | 2 | Yes | 00011 | Multinode Not in scope |
| All | No | Yes | 1 | No | 00100 | Covered |
| All | No | Yes | 1 | Yes | 00101 |  Covered |
| All | No | Yes | 2 | No | 00110 | Multinode Not in scope |
| All | No | Yes | 2 | Yes | 00111 | Multinode Not in scope |
| All | Yes | No | 1 | No | 01000 | Covered |
| All | Yes | No | 1 | Yes | 01001 | Covered |
| All | Yes | No | 2 | No | 01010 | Multinode Not in scope |
| All | Yes | No | 2 | Yes | 01011 | Multinode Not in scope|
| All | Yes | Yes | 1 | No | 01100 | Covered |
| All | Yes | Yes | 1 | Yes | 01101 | Covered | 
| All | Yes | Yes | 2 | No | 01110 | Multinode Not in scope |
| All | Yes | Yes | 2 | Yes | 01111 | Multinode Not in scope |
| ID | No | No | 1 | No | 10000 | Covered |
| ID | No | No | 1 | Yes | 10001 | Not a valid scenario. Covered |
| ID | No | No | 2 | No | 10010 | Multinode Not in scope |
| ID | No | No | 2 | Yes | 10011 | Multinode Not in scope |
| ID | No | Yes | 1 | No | 10100 | Covered |
| ID | No | Yes | 1 | Yes | 10101 |  Not a valid scenario |
| ID | No | Yes | 2 | No | 10110 | Multinode Not in scope |
| ID | No | Yes | 2 | Yes | 10111 | Multinode Not in scope |
| ID | Yes | No | 1 | No | 11000 | Covered |
| ID | Yes | No | 1 | Yes | 11001 | Not a valid scenario. Covered |
| ID | Yes | No | 2 | No | 11010 | Multinode Not in scope |
| ID | Yes | No | 2 | Yes | 11011 | Multinode Not in scope|
| ID | Yes | Yes | 1 | No | 11100 | Covered |
| ID | Yes | Yes | 1 | Yes | 11101 | Not a valid scenario | 
| ID | Yes | Yes | 2 | No | 11110 | Multinode Not in scope |
| ID | Yes | Yes | 2 | Yes | 11111 | Multinode Not in scope |