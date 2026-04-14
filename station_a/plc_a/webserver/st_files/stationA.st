PROGRAM poste_elevateur

  (* POSTE ELEVATEUR HTA/HTB - Station A *)
  (* Role : elever la tension 20 kV HTA -> 90 kV HTB *)
  (* Cycle : T#50ms | OpenPLC Runtime | Modbus TCP port 502 *)
  (*                                                        *)
  (* ADRESSES MODBUS :                                      *)
  (*   QX coils  -> FC01/FC05  boutons CMD                 *)
  (*   IX inputs -> FC02       statuts STS et alarmes ALM  *)
  (*   MW memory -> FC03/FC06  consignes SET et mesures MET*)
  (*                                                        *)
  (* REGLE parse_st : UN SEUL ESPACE entre chaque token    *)
  (* La fonction parse_st fait split sur espace simple.    *)
  (* Plusieurs espaces creent des tokens vides et decalent  *)
  (* les indices -> adresse non trouvee -> valeur = 0.     *)
  (*   OK  : NomVar AT %MWn : TYPE;                        *)
  (*   NON : NomVar   AT %MWn  : TYPE;  <- espaces multiples*)
  (*                                                        *)
  (* REGLE MW vs IW :                                       *)
  (*   IW = registres lies au hardware. Sans hardware = 0. *)
  (*   MW = memoire interne que le programme PLC peut ecrire*)

  (* --- COMMANDES : Coils QX0.0 a QX1.0 --- *)
  VAR
    CMD_Arrivee_CB AT %QX0.0 : BOOL;
    CMD_DS_Ligne AT %QX0.1 : BOOL;
    CMD_DS_Bus_HTA AT %QX0.2 : BOOL;
    CMD_TX1_CB_Amont AT %QX0.3 : BOOL;
    CMD_TX1_CB_Aval AT %QX0.4 : BOOL;
    CMD_TX2_CB_Amont AT %QX0.5 : BOOL;
    CMD_TX2_CB_Aval AT %QX0.6 : BOOL;
    CMD_Depart_HTB1_CB AT %QX0.7 : BOOL;
    CMD_Depart_HTB2_CB AT %QX1.0 : BOOL;
  END_VAR

  (* --- STATUTS : Discrete Inputs IX0.0 a IX0.5 --- *)
  VAR
    STS_HTA_Bus_Alimente AT %IX0.0 : BOOL;
    STS_HTB_Bus_Alimente AT %IX0.1 : BOOL;
    STS_TX1_En_Service AT %IX0.2 : BOOL;
    STS_TX2_En_Service AT %IX0.3 : BOOL;
    STS_Depart_HTB1_Actif AT %IX0.4 : BOOL;
    STS_Depart_HTB2_Actif AT %IX0.5 : BOOL;
  END_VAR

  (* --- ALARMES TENSION/FREQ : IX1.0 a IX1.5 --- *)
  VAR
    ALM_HTA_Surtension AT %IX1.0 : BOOL;
    ALM_HTA_Sous_Tension AT %IX1.1 : BOOL;
    ALM_HTB_Surtension AT %IX1.2 : BOOL;
    ALM_HTB_Sous_Tension AT %IX1.3 : BOOL;
    ALM_Freq_Haute AT %IX1.4 : BOOL;
    ALM_Freq_Basse AT %IX1.5 : BOOL;
  END_VAR

  (* --- ALARMES THERMIQUES : IX2.0 a IX2.7 --- *)
  VAR
    ALM_TX1_Huile_Haute AT %IX2.0 : BOOL;
    ALM_TX1_Huile_Crit AT %IX2.1 : BOOL;
    ALM_TX1_Enroul_Haute AT %IX2.2 : BOOL;
    ALM_TX1_Enroul_Crit AT %IX2.3 : BOOL;
    ALM_TX2_Huile_Haute AT %IX2.4 : BOOL;
    ALM_TX2_Huile_Crit AT %IX2.5 : BOOL;
    ALM_TX2_Enroul_Haute AT %IX2.6 : BOOL;
    ALM_TX2_Enroul_Crit AT %IX2.7 : BOOL;
  END_VAR

  (* --- ALARMES PROTECTION : IX3.0 a IX3.5 --- *)
  VAR
    ALM_TX1_Surcharge AT %IX3.0 : BOOL;
    ALM_TX1_Buchholz AT %IX3.1 : BOOL;
    ALM_TX2_Surcharge AT %IX3.2 : BOOL;
    ALM_TX2_Buchholz AT %IX3.3 : BOOL;
    ALM_Depart_Surcharge AT %IX3.4 : BOOL;
    ALM_Alim_Critique AT %IX3.5 : BOOL;
  END_VAR

  (* --- CONSIGNES : MW0 a MW3 - ecriture SCADA via FC06 --- *)
  VAR
    SET_TX1_Tension_HTB AT %MW0 : INT;
    SET_TX2_Tension_HTB AT %MW1 : INT;
    SET_Charge_Depart1 AT %MW2 : INT;
    SET_Charge_Depart2 AT %MW3 : INT;
  END_VAR

  (* --- MESURES : MW4 a MW23 - ecriture PLC, lecture SCADA FC03 --- *)
  VAR
    MET_HTA_Tension AT %MW4 : INT;
    MET_HTA_Courant AT %MW5 : INT;
    MET_Frequence AT %MW6 : INT;
    MET_HTA_Puissance AT %MW7 : INT;
    MET_HTA_Cos_Phi AT %MW8 : INT;
    MET_HTB_Tension AT %MW9 : INT;
    MET_HTB_Courant AT %MW10 : INT;
    MET_HTB_Puissance AT %MW11 : INT;
    MET_TX1_Temp_Huile AT %MW12 : INT;
    MET_TX1_Temp_Enroul AT %MW13 : INT;
    MET_TX1_I_HTA AT %MW14 : INT;
    MET_TX1_I_HTB AT %MW15 : INT;
    MET_TX2_Temp_Huile AT %MW16 : INT;
    MET_TX2_Temp_Enroul AT %MW17 : INT;
    MET_TX2_I_HTA AT %MW18 : INT;
    MET_TX2_I_HTB AT %MW19 : INT;
    MET_Dep1_Courant AT %MW20 : INT;
    MET_Dep1_Puissance AT %MW21 : INT;
    MET_Dep2_Courant AT %MW22 : INT;
    MET_Dep2_Puissance AT %MW23 : INT;
  END_VAR

  (* Variables internes - calculs, pas visibles Modbus *)
  VAR
    SIM_Timer : REAL := 0.0;
    First_Cycle : BOOL := TRUE;
    _HTA_V : REAL;
    _HTB_V : REAL;
    _Freq : REAL;
    _HTA_I : REAL;
    _HTB_I : REAL;
    _Cos_Phi : REAL;
    _TX1_I_HTA : REAL;
    _TX1_I_HTB : REAL;
    _TX2_I_HTA : REAL;
    _TX2_I_HTB : REAL;
    _TX1_OilTemp : REAL;
    _TX1_WndTemp : REAL;
    _TX2_OilTemp : REAL;
    _TX2_WndTemp : REAL;
    _D1_I : REAL;
    _D1_P : REAL;
    _D2_I : REAL;
    _D2_P : REAL;
    _Noise : REAL;
    _HTB_V_Sum : REAL;
    _HTB_V_Count : REAL;
    _TX_Count : REAL;
    _Th_Target1 : REAL;
    _Th_Target2 : REAL;
  END_VAR


  (* === A - INITIALISATION premier cycle === *)

  IF First_Cycle THEN
    SET_TX1_Tension_HTB := 90;
    SET_TX2_Tension_HTB := 90;
    SET_Charge_Depart1 := 70;
    SET_Charge_Depart2 := 65;
    CMD_Arrivee_CB := TRUE;
    CMD_DS_Ligne := TRUE;
    CMD_DS_Bus_HTA := TRUE;
    CMD_TX1_CB_Amont := TRUE;
    CMD_TX1_CB_Aval := TRUE;
    CMD_TX2_CB_Amont := TRUE;
    CMD_TX2_CB_Aval := TRUE;
    CMD_Depart_HTB1_CB := TRUE;
    CMD_Depart_HTB2_CB := TRUE;
    _TX1_OilTemp := 45.0;
    _TX2_OilTemp := 45.0;
    SIM_Timer := 0.0;
    First_Cycle := FALSE;
  END_IF;


  (* === B - TIMER ET BRUIT === *)

  SIM_Timer := SIM_Timer + 0.05;
  IF SIM_Timer > 6283.0 THEN SIM_Timer := 0.0; END_IF;
  _Noise := SIN(SIM_Timer * 11.3) * 0.12 + COS(SIM_Timer * 7.7) * 0.07;


  (* === C - BORNAGE DES CONSIGNES === *)

  IF SET_TX1_Tension_HTB < 80 THEN SET_TX1_Tension_HTB := 80; END_IF;
  IF SET_TX1_Tension_HTB > 100 THEN SET_TX1_Tension_HTB := 100; END_IF;
  IF SET_TX2_Tension_HTB < 80 THEN SET_TX2_Tension_HTB := 80; END_IF;
  IF SET_TX2_Tension_HTB > 100 THEN SET_TX2_Tension_HTB := 100; END_IF;
  IF SET_Charge_Depart1 < 0 THEN SET_Charge_Depart1 := 0; END_IF;
  IF SET_Charge_Depart1 > 100 THEN SET_Charge_Depart1 := 100; END_IF;
  IF SET_Charge_Depart2 < 0 THEN SET_Charge_Depart2 := 0; END_IF;
  IF SET_Charge_Depart2 > 100 THEN SET_Charge_Depart2 := 100; END_IF;


  (* === D - INTERLOCKS DE SECURITE === *)

  IF CMD_Arrivee_CB THEN
    CMD_DS_Ligne := TRUE;
    CMD_DS_Bus_HTA := TRUE;
  END_IF;
  IF NOT CMD_Arrivee_CB THEN
    CMD_TX1_CB_Amont := FALSE;
    CMD_TX1_CB_Aval := FALSE;
    CMD_TX2_CB_Amont := FALSE;
    CMD_TX2_CB_Aval := FALSE;
    CMD_Depart_HTB1_CB := FALSE;
    CMD_Depart_HTB2_CB := FALSE;
  END_IF;
  IF NOT CMD_TX1_CB_Amont THEN CMD_TX1_CB_Aval := FALSE; END_IF;
  IF NOT CMD_TX2_CB_Amont THEN CMD_TX2_CB_Aval := FALSE; END_IF;
  IF NOT STS_HTB_Bus_Alimente THEN
    CMD_Depart_HTB1_CB := FALSE;
    CMD_Depart_HTB2_CB := FALSE;
  END_IF;


  (* === E - TOPOLOGIE === *)

  STS_HTA_Bus_Alimente := CMD_Arrivee_CB AND CMD_DS_Ligne AND CMD_DS_Bus_HTA;
  STS_TX1_En_Service := STS_HTA_Bus_Alimente AND CMD_TX1_CB_Amont AND CMD_TX1_CB_Aval;
  STS_TX2_En_Service := STS_HTA_Bus_Alimente AND CMD_TX2_CB_Amont AND CMD_TX2_CB_Aval;
  STS_HTB_Bus_Alimente := STS_TX1_En_Service OR STS_TX2_En_Service;
  STS_Depart_HTB1_Actif := STS_HTB_Bus_Alimente AND CMD_Depart_HTB1_CB;
  STS_Depart_HTB2_Actif := STS_HTB_Bus_Alimente AND CMD_Depart_HTB2_CB;


  (* === F - FREQUENCE RESEAU === *)

  IF STS_HTA_Bus_Alimente THEN
    _Freq := 50.0 + SIN(SIM_Timer * 0.08) * 0.12 + _Noise * 0.03;
  ELSE
    _Freq := 0.0;
  END_IF;
  MET_Frequence := REAL_TO_INT(_Freq * 10.0);


  (* === G - TENSION HTA nominale 20 kV === *)

  IF STS_HTA_Bus_Alimente THEN
    _HTA_V := 20.0 + SIN(SIM_Timer * 0.04) * 0.25 + _Noise * 0.04;
  ELSE
    _HTA_V := 0.0;
  END_IF;
  MET_HTA_Tension := REAL_TO_INT(_HTA_V * 10.0);


  (* === H - TENSION HTB nominale 90 kV, rapport 4.5 === *)

  _HTB_V_Sum := 0.0;
  _HTB_V_Count := 0.0;
  IF STS_TX1_En_Service THEN
    _HTB_V_Sum := _HTB_V_Sum + INT_TO_REAL(SET_TX1_Tension_HTB);
    _HTB_V_Count := _HTB_V_Count + 1.0;
  END_IF;
  IF STS_TX2_En_Service THEN
    _HTB_V_Sum := _HTB_V_Sum + INT_TO_REAL(SET_TX2_Tension_HTB);
    _HTB_V_Count := _HTB_V_Count + 1.0;
  END_IF;
  IF STS_HTB_Bus_Alimente AND (_HTB_V_Count > 0.0) THEN
    _HTB_V := (_HTB_V_Sum / _HTB_V_Count) + SIN(SIM_Timer * 0.03) * 0.4 + _Noise * 0.08;
  ELSE
    _HTB_V := 0.0;
  END_IF;
  MET_HTB_Tension := REAL_TO_INT(_HTB_V * 10.0);


  (* === I - COURANTS ET PUISSANCES === *)
  (* Capacite nominale : 220 A a 90 kV par depart *)

  _Cos_Phi := 0.92 + SIN(SIM_Timer * 0.06) * 0.015;
  MET_HTA_Cos_Phi := REAL_TO_INT(_Cos_Phi * 100.0);

  IF STS_Depart_HTB1_Actif THEN
    _D1_I := (INT_TO_REAL(SET_Charge_Depart1) / 100.0) * 220.0 + SIN(SIM_Timer * 0.18) * 5.0 + _Noise * 2.0;
    _D1_P := (_D1_I * _HTB_V * 1.732 * _Cos_Phi) / 1000.0;
  ELSE
    _D1_I := 0.0;
    _D1_P := 0.0;
  END_IF;

  IF STS_Depart_HTB2_Actif THEN
    _D2_I := (INT_TO_REAL(SET_Charge_Depart2) / 100.0) * 220.0 + COS(SIM_Timer * 0.22) * 4.0 + _Noise * 1.5;
    _D2_P := (_D2_I * _HTB_V * 1.732 * _Cos_Phi) / 1000.0;
  ELSE
    _D2_I := 0.0;
    _D2_P := 0.0;
  END_IF;

  MET_Dep1_Courant := REAL_TO_INT(_D1_I);
  MET_Dep1_Puissance := REAL_TO_INT(_D1_P);
  MET_Dep2_Courant := REAL_TO_INT(_D2_I);
  MET_Dep2_Puissance := REAL_TO_INT(_D2_P);

  _HTB_I := _D1_I + _D2_I;
  MET_HTB_Courant := REAL_TO_INT(_HTB_I);
  MET_HTB_Puissance := REAL_TO_INT(_D1_P + _D2_P);

  _TX_Count := 0.0;
  IF STS_TX1_En_Service THEN _TX_Count := _TX_Count + 1.0; END_IF;
  IF STS_TX2_En_Service THEN _TX_Count := _TX_Count + 1.0; END_IF;

  IF _TX_Count > 0.0 THEN
    IF STS_TX1_En_Service THEN
      _TX1_I_HTB := _HTB_I / _TX_Count;
    ELSE
      _TX1_I_HTB := 0.0;
    END_IF;
    IF STS_TX2_En_Service THEN
      _TX2_I_HTB := _HTB_I / _TX_Count;
    ELSE
      _TX2_I_HTB := 0.0;
    END_IF;
  ELSE
    _TX1_I_HTB := 0.0;
    _TX2_I_HTB := 0.0;
  END_IF;

  _TX1_I_HTA := _TX1_I_HTB * 4.5;
  _TX2_I_HTA := _TX2_I_HTB * 4.5;
  _HTA_I := _TX1_I_HTA + _TX2_I_HTA;

  MET_TX1_I_HTB := REAL_TO_INT(_TX1_I_HTB);
  MET_TX1_I_HTA := REAL_TO_INT(_TX1_I_HTA);
  MET_TX2_I_HTB := REAL_TO_INT(_TX2_I_HTB);
  MET_TX2_I_HTA := REAL_TO_INT(_TX2_I_HTA);
  MET_HTA_Courant := REAL_TO_INT(_HTA_I);
  MET_HTA_Puissance := REAL_TO_INT((_HTA_V * _HTA_I * 1.732 * _Cos_Phi) / 1000.0);


  (* === J - MODELE THERMIQUE TRANSFORMATEURS === *)
  (* Equilibre = 55 C + courant_HTB x 0.10 *)
  (* 220A nominal : 77 C -> normal *)
  (* 440A surcharge : 99 C -> Buchholz + Huile_Crit *)

  IF STS_TX1_En_Service THEN
    _Th_Target1 := 55.0 + _TX1_I_HTB * 0.10;
    IF _TX1_OilTemp < _Th_Target1 THEN
      _TX1_OilTemp := _TX1_OilTemp + 0.4;
    ELSIF _TX1_OilTemp > (_Th_Target1 + 2.0) THEN
      _TX1_OilTemp := _TX1_OilTemp - 0.2;
    END_IF;
    _TX1_WndTemp := _TX1_OilTemp + 8.0 + (_TX1_I_HTB * _TX1_I_HTB * 0.00028);
  ELSE
    IF _TX1_OilTemp > 25.0 THEN _TX1_OilTemp := _TX1_OilTemp - 0.2; END_IF;
    _TX1_WndTemp := _TX1_OilTemp;
  END_IF;
  MET_TX1_Temp_Huile := REAL_TO_INT(_TX1_OilTemp);
  MET_TX1_Temp_Enroul := REAL_TO_INT(_TX1_WndTemp);

  IF STS_TX2_En_Service THEN
    _Th_Target2 := 54.0 + _TX2_I_HTB * 0.10;
    IF _TX2_OilTemp < _Th_Target2 THEN
      _TX2_OilTemp := _TX2_OilTemp + 0.4;
    ELSIF _TX2_OilTemp > (_Th_Target2 + 2.0) THEN
      _TX2_OilTemp := _TX2_OilTemp - 0.2;
    END_IF;
    _TX2_WndTemp := _TX2_OilTemp + 8.0 + (_TX2_I_HTB * _TX2_I_HTB * 0.00028);
  ELSE
    IF _TX2_OilTemp > 25.0 THEN _TX2_OilTemp := _TX2_OilTemp - 0.2; END_IF;
    _TX2_WndTemp := _TX2_OilTemp;
  END_IF;
  MET_TX2_Temp_Huile := REAL_TO_INT(_TX2_OilTemp);
  MET_TX2_Temp_Enroul := REAL_TO_INT(_TX2_WndTemp);


  (* === K - ALARMES TENSION ET FREQUENCE === *)

  ALM_HTA_Surtension := STS_HTA_Bus_Alimente AND (_HTA_V > 22.0);
  ALM_HTA_Sous_Tension := STS_HTA_Bus_Alimente AND (_HTA_V < 18.0);
  ALM_HTB_Surtension := STS_HTB_Bus_Alimente AND (_HTB_V > 99.0);
  ALM_HTB_Sous_Tension := STS_HTB_Bus_Alimente AND (_HTB_V < 81.0);
  ALM_Freq_Haute := STS_HTA_Bus_Alimente AND (_Freq > 50.5);
  ALM_Freq_Basse := STS_HTA_Bus_Alimente AND (_Freq < 49.5);


  (* === L - ALARMES THERMIQUES === *)

  ALM_TX1_Huile_Haute := (_TX1_OilTemp >= 80.0);
  ALM_TX1_Huile_Crit := (_TX1_OilTemp >= 95.0);
  ALM_TX1_Enroul_Haute := (_TX1_WndTemp >= 90.0);
  ALM_TX1_Enroul_Crit := (_TX1_WndTemp >= 105.0);
  ALM_TX2_Huile_Haute := (_TX2_OilTemp >= 80.0);
  ALM_TX2_Huile_Crit := (_TX2_OilTemp >= 95.0);
  ALM_TX2_Enroul_Haute := (_TX2_WndTemp >= 90.0);
  ALM_TX2_Enroul_Crit := (_TX2_WndTemp >= 105.0);


  (* === M - ALARMES PROTECTION ELECTRIQUE === *)

  ALM_TX1_Surcharge := (_TX1_I_HTB > 279.0);
  ALM_TX2_Surcharge := (_TX2_I_HTB > 279.0);
  ALM_TX1_Buchholz := ALM_TX1_Huile_Crit;
  ALM_TX2_Buchholz := ALM_TX2_Huile_Crit;
  ALM_Depart_Surcharge := (_HTB_I > 418.0);
  ALM_Alim_Critique :=
    (STS_TX1_En_Service AND NOT STS_TX2_En_Service AND (_TX1_I_HTB > 200.0))
    OR
    (STS_TX2_En_Service AND NOT STS_TX1_En_Service AND (_TX2_I_HTB > 200.0));


END_PROGRAM


CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : poste_elevateur;
  END_RESOURCE
END_CONFIGURATION
