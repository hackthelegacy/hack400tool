//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2017  Bart Kulach
//    This file, IBMiAuditor.java, is part of hack400tool package.

//    "hack400tool" is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.

//    "hack400tool" is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
package org.hackthelegacy.hack400tool.ibmiscannercore;

import com.ibm.as400.access.AS400SecurityException;
import com.ibm.as400.access.ErrorCompletingRequestException;
import com.ibm.as400.access.ObjectDoesNotExistException;
import java.beans.PropertyVetoException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Vector;
import javax.swing.table.DefaultTableModel;

public class IBMiAuditor extends IBMiConnector{

    private SqliteDbConnector settingsDB;
    private SqliteDbConnector reportDB;
    
    private String systemNameTable;

    
    public IBMiAuditor(String serverAddress, boolean useSSL, boolean useJDBC, 
                        String temporaryLibrary, String userName, String password) 
            throws AS400SecurityException, IOException, ErrorCompletingRequestException, 
            InterruptedException, PropertyVetoException, ObjectDoesNotExistException, 
            SQLException, KeyManagementException, NoSuchAlgorithmException {
        super(serverAddress, useSSL, useJDBC, temporaryLibrary, userName, password);
        reportDB = new SqliteDbConnector(new SimpleDateFormat("YYMMddHHmmSS").format(new Date()), true);
        systemNameTable = reportDB.createTempTable("systemName", 1);
        Vector systemNameVector = new Vector();
        systemNameVector.add(serverAddress);
        reportDB.insertrow(systemNameTable, systemNameVector);
        settingsDB = new SqliteDbConnector("IBMiAuditor.db");
    }
    
    public String getReportDBName(){
        return reportDB.getDatabaseFileName();
    }
    
    public String getSystemTableName(){
        return systemNameTable;
    }
    
    public String checkSystemValues() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            ObjectDoesNotExistException, InterruptedException, IOException, 
            SQLException {
        
        DefaultTableModel sysVals;
        
        //Results table:
        //-score
        //-Value name
        //-Current value
        //-Expected value
        //-Impact
        
        String compTable = reportDB.createTempTable("reportsystemvalues", 5);
                
        sysVals = getAllSystemValues();
        for (int i=1; i<sysVals.getRowCount(); i++) {
            Vector sysValReportEntry = new Vector();
            String sysValName = sysVals.getValueAt(i, 0).toString();
            String sysValValue = sysVals.getValueAt(i, 1).toString();
            String sysValDescription = sysVals.getValueAt(i, 2).toString();
            DefaultTableModel sysValDetails = settingsDB.query
                                            ("SELECT expectedvalue, description FROM systemvaluetypes WHERE name = ?", new String[]{sysValName})
                                            .toTableModel();
            
            //if nothing found, the system value is not scored
            if (sysValDetails.getRowCount() != 1) 
            {
                sysValReportEntry.addElement("INFO");
                sysValReportEntry.addElement(sysValName);
                sysValReportEntry.addElement(sysValValue);
                sysValReportEntry.addElement("N/A");
                sysValReportEntry.addElement(sysValDescription);
                reportDB.insertrow(compTable, sysValReportEntry);
                continue;
            }
            
            String score = "RED";    //if value couldn't match, it means the score is amber by definition
            DefaultTableModel sysValScores = settingsDB.query
                                            ("SELECT sysvalue, comparetype, score FROM systemvalues WHERE name = ?", new String[] {sysValName})
                                            .toTableModel();
            
            //Variables for use in table comparisons
            String[] sysValValues;
            String[] sysValScoreTable;
            int sysValueInt;
            compareLoop: for (int j=0; j<sysValScores.getRowCount(); j++) {
                switch (sysValScores.getValueAt(j, 1).toString()) {
                    case "GREATEREQUAL":
                        try {
                            sysValueInt = Integer.valueOf(sysValValue);
                        } catch (NumberFormatException ex) {
                            break;
                        }                        
                        if (sysValueInt >= Integer.valueOf(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "LOWEREQUAL":
                        try {
                            sysValueInt = Integer.valueOf(sysValValue);
                        } catch (NumberFormatException ex) {
                            break;
                        }                        
                        if (sysValueInt <= Integer.valueOf(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "GREATER":
                        try {
                            sysValueInt = Integer.valueOf(sysValValue);
                        } catch (NumberFormatException ex) {
                            break;
                        }                        
                        if (sysValueInt > Integer.valueOf(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "LOWER":
                        try {
                            sysValueInt = Integer.valueOf(sysValValue);
                        } catch (NumberFormatException ex) {
                            break;
                        }                        
                        if (sysValueInt < Integer.valueOf(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "CONTAINS":
                        sysValValues = sysValValue.split(" ");
                        sysValScoreTable = sysValScores.getValueAt(j, 0).toString().split(" ");
                        if (Arrays.asList(sysValValues).containsAll(Arrays.asList(sysValScoreTable))) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "DOESNOTCONTAIN":
                        sysValValues = sysValValue.split(" ");
                        sysValScoreTable = sysValScores.getValueAt(j, 0).toString().split(" ");
                        Collection sysValColl = new ArrayList(Arrays.asList(sysValValues));
                        if (sysValColl.removeAll(Arrays.asList(sysValScoreTable)) == false) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    case "DOESNOTEQUAL":
                        if (!sysValValue.equalsIgnoreCase(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                        break;
                    default:
                    case "EQUALS":
                        if (sysValValue.equalsIgnoreCase(sysValScores.getValueAt(j, 0).toString())) {
                            score = sysValScores.getValueAt(j, 2).toString();
                            if (score=="GREEN") break compareLoop;
                        }
                }    
            }            
            sysValReportEntry.addElement(score);
            sysValReportEntry.addElement(sysValName);
            sysValReportEntry.addElement(sysValValue);
            sysValReportEntry.addElement(sysValDetails.getValueAt(0, 0).toString());
            sysValReportEntry.addElement(sysValDescription/*sysValDetails.getValueAt(0, 1).toString()*/);
            reportDB.insertrow(compTable, sysValReportEntry);
        }        
        return compTable;
    }
    
    public String checkInsecurePorts() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, 
            InterruptedException, ObjectDoesNotExistException, SQLException {
        
        //Results table:
        //-score
        //-Finding
        //-Impact
        
        String netStatTable = getNetStat();
        
        //Refer to NCNN0100 Format. Selects local address and open port which are in listening state (0)
        DefaultTableModel listeningPorts =  queryResultsTable
                                        ("SELECT _7, _13 FROM " + netStatTable + " WHERE _8 = 0 AND _7 != 0");
        
        DefaultTableModel portList = settingsDB.query
                                    ("SELECT portnumber FROM insecureports")
                                    .toTableModel();
        
        List<String> insecurePorts = new ArrayList<>();
        String[] portListArray = IBMiUtilities.arrayFromDataTableModel(portList);
        
        for (int i=0; i<listeningPorts.getRowCount(); i++) {
            String port = listeningPorts.getValueAt(i, 0).toString() 
                            + "/" + listeningPorts.getValueAt(i, 1).toString().substring(1);
            if (Arrays.asList(portListArray).contains(port.toLowerCase()))
                insecurePorts.add(port);
        }
        
        Vector insecurePortsReportEntry = new Vector();
        String compTable = reportDB.createTempTable("reportinsecureports", 2);

        if (!insecurePorts.isEmpty()) {                
            DefaultTableModel reportInput = settingsDB.query
                                        ("SELECT score, explanation FROM genericdescriptions WHERE area = 'insecureports'")
                                        .toTableModel();

            String score = reportInput.getValueAt(0, 0).toString();
            String explanation = reportInput.getValueAt(0, 1).toString();        
            explanation += IBMiUtilities.stringFromArray(insecurePorts.toArray(new String[0]), ", ");

            //Results table:
            //-score
            //-explanation
            
            insecurePortsReportEntry.addElement(score);
            insecurePortsReportEntry.addElement(explanation);
        } else {
            insecurePortsReportEntry.addElement("GREEN");
            insecurePortsReportEntry.addElement("No insecure ports found.");
        }
        reportDB.insertrow(compTable, insecurePortsReportEntry);
        
        return compTable;
    }    
}
