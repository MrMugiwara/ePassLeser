ePassLeser v0.1

dient zum Auslesen des Gesichtsbildes per BAC
aus einem elektronischen Reisepass
oder Aufenthaltstitel


QnD-Implementierung

=============================================

Copyright (C) 2014  Adrian Krohn
E-mail: adk@toppoint.de

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

=============================================

1.) Was kann das Programm?

Das Programm ließt über ein angeschlossenes PC/SC-Lesegerät das Gesichtsbild im JPEG2000-Format aus Datengruppe 2 eines elektronischen Reisepasses (ePass) oder eines elektronischen Aufenthaltstitel (eAt) über "Basic Access Control" aus und speichert es als bild.jp2 im Arbeitsverzeichnis ab.

2.) Kompilieren
Das Programm wird mithilfe des java-Compilers kompiliert:

cd ./ePassLeser-0.1
javac ePassLeser.java

3.) Inbetriebnahme
Um das Programm auszuführen muss der PC/SC-Leser vorher angeschlossen und installiert sein.
Im Programmverzeichnis wird dann in der Konsole

java ePassLeser

aufgerufen und im Programm dann die entsprechende Nummer des PC/SC-Lesers eingegeben.
Es wird nun nach der 9-stelligen Dokumentennummer und der Prüfziffer gefragt, welche in der maschinenlesbaren Zone des Dokumentes abgelesen werden kann. Selbiges gilt für das Geburtsdatum und das Ablaufdatum.

Danach wird das Dokument auf das Lesegerät gelegt.

Sofern die Daten korrekt eingegeben worden sind, wird das Bild übertragen und im Arbeitsverzeichnis als bild.jp2 abgespeichert, wo es dann weiterverarbeitet werden kann. Eine eventuell vorhandende Datei wird ohne Nachfrage überschrieben.



Für weitere Informationen bezüglich BAC und SecureMessaging bitte ICAO-Dokument 9303 Part 1 Volume 2 konsultieren:
http://www.icao.int/publications/Documents/9303_p1_v2_cons_en.pdf
http://www.icao.int/publications/pages/publication.aspx?docnum=9303


