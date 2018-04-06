# Voimalaitosdatan visualisointityökalun jatkokehitys

## Johdanto

Kristian Laakkonen toteutti diplomityönään selainpohjaisen tietojärjestelmän, jonka avulla voidaan havainnollistaa prosessitietoja käyttäjäystävällisesti. Tietojärjestelmässä voidaan luoda käyttäjille helppolukuisia prosessikaavionäyttöjä. Järjestelmä tehtiin, koska aikaisemmissa työpöytäsovelluksissa on ollut omat rajoitteensa. Esimerkiksi työpöytäsovellukset täytyy asentaa erikseen kaikille tietokoneille ja ne on usein sidottu vain yhdelle käyttöjärjestelmälle ja myös ohjelmistojen päivitys on täytynyt tehdä jokaiselle koneelle erikseen. Diplomityönä valmistunut selainpohjainen järjestelmä korjasi nuo puutteet. Työasema tarvitsee vain web-selaimen, jonka avulla käyttäjä pääsee käyttämään järjestelmää. Järjestelmän ylläpito ja päivitykset tapahtuvat palvelinpäässä ja loppukäyttäjien suunnalta ei tarvita toimenpiteitä.

## Spring

## Scrum

## ProView

## 1. Sprintti

### Sprintin suunnittelu

Ensimmäisen sprintin suunnittelussa keskityttiin miettimään sidosryhmien kanssa opinnäytetyön laajuutta. Tuoteomistaja oli miettinyt tarpeelliset kehitysaihiot ProView 1.1 -kehitystyötä varten, ja näistä valittiin sopiva kokonaisuus, joka oli laajudessaan sopiva opinnäytetyötä varten. Opinnäytetyötä varten valittiin seuraavat kehitysaihiot:
- ProView:n editorityökalussa oleva ruudukko-ominaisuus olisi oletuksena päällä
- Uusille piirrettäville näytöille lisää resoluutiovaihtoehtoja ja oletusresoluutioksi 1920x1080 pikseliä
- Työkaluun haluttiin pikanäppäin painike, joka helpottaisi työskentelyä
- Visuaalisten komponenttien (muuttuja, muuttujalista, taulukko, graafi) lisäyspainikkeiden uudelleensijoittelu
- Uusille näytöille automaattinen vesileima, joka toimisi ilmaisena mainoksena kaikissa piirretyissä näytöissä
- Editorissa olevaan tekstityökaluun rivinvaihto-ominaisuus
- Editorissa olevien kirjastokomponenttien yhtenäistäminen virallisiin julkaisuversioihin
- Mittauksien / laskettujen arvojen automatisointi
- Zoomaustyökalun käytettävyyden helpottaminen
- Muuttujalistaan näkyviin lisää dataa (muuttujien min ja max raja-arvot, muuttujien status)

Sprintin suunnittelussa myös päätettiin, että kyseiset kehitysaihiot ovat vain minun työlistallani ja muut Scrum teamin jäsenet eivät ota niitä omalle työlistalleen. Minulle annettiin vapaat kädet päättää, että missä järjestyksessä teen tarvitttavat työt.

### Sprintin työskentely

Valitsin ensimmäiseksi työtehtäväksi visuaalisten komponenttien uudelleensijoittelun. Lähtötilanne oli, että valittavat komponentit oli oman näkymän takana ja ne haluttiin siirtää ProView:n vasemmalla olevaan työkalupalkkiin muiden sekaan. Koodin puolelta tämä muutos tapahtui niin, että siirsin nämä erillisessä näkymässä olevat metodit, jotka lisäävät komponentteja ProView:n perusnäkymässä tapahtuvaan ohjelmakoodiin ja sijoitin halutut napit oikeille paikoille. Nappien kuvatkin löytyivät sopivasti valmiina ohjelmakoodin seasta, joten täytyi vain laittaa polut oikein. Tämän jälkeen tuo "valitse lisättävä komponentti" -näkymä oli luonnollisesti turha, joten sen pystyi kokonaan poistamaan.

Toinen työtehtävä liittyi resoluutioiden lisäämiseen ja oletusresoluution vaihtamiseen. Hetken koodia tutkittuani huomasin, että oletusresoluutio ja resoluutiovaihtoehdot oli kovakoodattu, joten pystyin vain suoraan lisäämään valmiisteen listaan uuden resoluutiovaihtoehdon.

Sprintin viimeiseksi tehtäväksi jäi ProView:ssa ProView:ssa olevan ruudukko-ominaisuuden päälle asettaminen oletuksena. Tähän tehtävään käytin kaikista eniten aikaa, sillä en meinannut millään löytää paikkaa, missä noita asioita käsitellään, mutta lopulta työtehtävä oli itsessään aika yksinkertainen. Lopulta löysin yhden JavaScript-olion, missä asetetaan uusien näyttöjen ja työkalujen oletustilat, joista minun täytyi muuttaa vaan yksi muuttuja false -> true.

### Sprintin katselmointi ja tulokset

Sprintin katselmoinnissa sidosryhmät tarkastelivat aikaan saatuja muutoksia, ja pääosin he olivat tyytyväisiä, mutta tuoteomistajalta tuli muutama korjauspyyntö. Komponenttien lisäyspainikkeiden kuvat haluttiin muuttaa, koska ne eivät sopineet yleiseen ulkoasuun muiden painikkeiden kanssa. Lisäksi uusi oletusresoluutio aiheutti sen, että uusi näyttö oli oletuksena zoomattu hieman liian lähelle. ProView:ssa on "sovita näyttöön" -toiminto erikseen, ja toiveena oli, että se tapahtuisi myös aina kun luodaan uusi näyttö. Muuten kaikkiin muihin muutoksiin oltiin tyytyväisiä. 

## 2. Sprintti

### Sprintin suunnittelu

### Sprintin katselmointi ja tulokset

## 3. Sprintti

## Sprintin suunnittelu

## Sprintin katselmointi ja tulokset

## 4. Sprintti

## Sprintin suunnittelu

## Sprintin katselmointi ja tulokset

## Lähteet

1. Kristian Laakkonen, Selainpohjainen tietojärjestelmä prosessitiedon havainnollistamiseen
