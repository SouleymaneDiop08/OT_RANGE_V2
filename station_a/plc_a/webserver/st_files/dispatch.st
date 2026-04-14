PROGRAM dispatch_electric
 
  VAR
  Int_Pylone AT %QX0.0 : BOOL := TRUE;
  Int_Pylone_status AT %IX0.0 : BOOL;
  Int_transform_A AT %QX0.1 : BOOL := TRUE;
  Int_transform_A_status AT %IX0.1 : BOOL;
  Int_transform_B_status AT %IX0.2 : BOOL;
  Int_transform_AetB_status AT %IX0.3 : BOOL;
  END_VAR
 
IF Int_Pylone THEN
  Int_Pylone_status := TRUE;
 
  IF Int_transform_A THEN
    Int_transform_B_status := FALSE;
  ELSE
    Int_transform_B_status := TRUE;
  END_IF;
 
  Int_transform_AetB_status := Int_Pylone_status;
  Int_transform_A_status := Int_transform_A;
  Int_transform_B_status := NOT Int_transform_A;
 
ELSE
  Int_Pylone_status := FALSE;
  Int_transform_A := FALSE;
  Int_transform_A_status := FALSE;
  Int_transform_B_status := FALSE;
  Int_transform_AetB_status := FALSE;
END_IF;
 
 
END_PROGRAM
 
CONFIGURATION Config0
 
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : dispatch_electric;
  END_RESOURCE
 
END_CONFIGURATION
