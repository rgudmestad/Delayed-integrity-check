# Delayed-integrity-check
 
Figuren visser hvordan løsningen fungerer. 
  - PMU.py representerer PMU-en som sender meldinger
  - hmac_PC.py representerer en datamaskin som subscriber på meldinger fra PMU-en, og lagger signaturer basert på disse meldingene
  - controll_pc.py representerer en datamaskin som også subcriber på meldinger fra PMU-en. den får også HMAC-er fra hmac_PC som den           sjekker opp mot hmacene som den selv har generert, basert på det same PMU meldingene.
  
![Image description] (https://user-images.githubusercontent.com/52523429/73827487-eb694a00-47ff-11ea-9e12-9762c41d1e2a.png)
