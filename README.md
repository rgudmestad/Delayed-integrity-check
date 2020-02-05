# Delayed-integrity-check
 
Figuren visser hvordan løsningen fungerer. 
  - PMU.py representerer PMU-en som sender meldinger
  - hmac_PC.py representerer en datamaskin som subscriber på meldinger fra PMU-en, og lagger signaturer basert på disse meldingene
  - controll_pc.py representerer en datamaskin som også subcriber på meldinger fra PMU-en. den får også HMAC-er fra hmac_PC som den           sjekker opp mot hmacene som den selv har generert, basert på det same PMU meldingene.
  
![Master-Page-1](https://user-images.githubusercontent.com/52523429/73828213-2455ee80-4801-11ea-9bd7-66760f7065b4.png)
