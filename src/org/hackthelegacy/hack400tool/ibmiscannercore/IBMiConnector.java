//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2016  Bart Kulach
//    This file, IBMiConnector.java, is part of hack400tool package.

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

import com.ibm.as400.access.*;
import java.awt.Color;
import java.awt.Component;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.awt.Frame;
import java.beans.PropertyVetoException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.StringReader;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.Icon;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JTree;
import javax.swing.ListModel;
import javax.swing.ProgressMonitor;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.event.ListDataListener;
import javax.swing.event.TreeModelListener;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class IBMiConnector {
    
    private AS400 insecureConnection = null;
    private SecureAS400 secureConnection = null;
    private boolean secure = false;
    private String curLib = "";
    private Job currentJob = null;
    private IFSFileTreeModel ifsTreeModel = null;
    private IFSFileListModel ifsListModel = null;
    private IFSFileTreeCellRenderer ifsFileTreeRenderer = null;
    private Connection JDBCConnection = null;
    private AS400JDBCDriver JDBCDriver = null;
    private AS400 JDBCSystem = null;
    
    private int currentTaskProgress = 0;
    private boolean isActiveTask = false;
    private boolean isCancelledTask = false;

    private SqliteDbConnector dbTempConnection;    
    
    private Statement JDBCStatement = null;
    
    private byte[][] userHandles = new byte[10][];
    private byte[][] userHandlesJDBC = new byte[10][];
    private int escalationLevel = 0;
    private int escalationLevelJDBC = 0;
    
    
    private int escalationUsersCurThreads = 0;
    private int objectListCurThreads = 0;
    
    public static final int CL_COMMAND_EXEC_PLAIN = 100;
    public static final int CL_COMMAND_EXEC_JDBC = 101;
    public static final int CL_COMMAND_EXEC_QSHELL = 102;
    
    public static final int PASSWORD_TYPE_NOPWD = 100;
    public static final int PASSWORD_TYPE_NOPWDCHK = 101;
    public static final int PASSWORD_TYPE_NOPWDSTS = 102;

    public static final int PASSWORD_HASH_FIRSTDES = 0;
    public static final int PASSWORD_HASH_SECONDDES = 1;
    public static final int PASSWORD_HASH_LMHASH = 2;
    public static final int PASSWORD_HASH_HMACSHA1UC = 3;
    public static final int PASSWORD_HASH_HMACSHA1MC = 6;
    public static final int PASSWORD_HASH_UNKNOWNHASH = 4;
    public static final int PASSWORD_HASH_ALLDATA = 5;    
    private static final int MAX_THREADS = 20;
    private static final int SLEEP_TIME = 100; 
    private static final int MAX_SLEEP = 5000; 
    
    private static final String DEFAULT_OUTQ_NAME = "HACKOUTQ";
    private static final String DEFAULT_SPLF_NAME = "HACKSPLF";
    
    public IBMiConnector(String serverAddress, boolean useSSL, boolean useJDBC, boolean useGUI, boolean useSockets, boolean useNetSockets, String temporaryLibrary, String userName, String password, boolean useProxy, String proxyServer) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException{
                
        
        if (useSSL) {
            if (userName.isEmpty() && password.isEmpty())
                secureConnection = new SecureAS400(serverAddress);
            else
                secureConnection = (useProxy ? new SecureAS400(serverAddress, userName, password, proxyServer) : new SecureAS400(serverAddress, userName, password));
            insecureConnection = null;
            secure = true;
        }
        else {
            if (userName.isEmpty() && password.isEmpty())
                insecureConnection = new AS400(serverAddress);
            else
                insecureConnection = (useProxy ? new AS400(serverAddress, userName, password, proxyServer) : new AS400(serverAddress, userName, password));
            secureConnection = null;
            secure = false;
        }
        
        (secure ? secureConnection : insecureConnection).setGuiAvailable(useGUI);
        (secure ? secureConnection : insecureConnection).setMustUseSockets(true);
        (secure ? secureConnection : insecureConnection).setMustUseNetSockets(true);   
        
        (secure ? secureConnection : insecureConnection).connectService(AS400.SIGNON);
        (secure ? secureConnection : insecureConnection).connectService(AS400.FILE);
        
        
        currentJob = new Job((secure ? secureConnection : insecureConnection));
        
        String message = "User " +
                " connected to " +
                (secure ? secureConnection : insecureConnection).getSystemName() + 
                ", version " + (secure ? secureConnection : insecureConnection).getVRM() +
                ", job number ";
        
        curLib = ((temporaryLibrary == null || temporaryLibrary.isEmpty()) ? "QTEMP" : temporaryLibrary.substring(0, (temporaryLibrary.length() < 10 ? temporaryLibrary.length() : 10)));
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, message);
        
        if (!curLib.matches("QTEMP")) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CRTLIB LIB(" + curLib + ")"));
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CLRLIB LIB(" + curLib + ")"));            
        }
        
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CRTPF FILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") RCDLEN(199) MAXMBRS(*NOMAX) SIZE(*NOMAX) LVLCHK(*NO)"));
        
        
        
        if (useJDBC)
        try {
            JDBCDriver = new AS400JDBCDriver();
            DriverManager.registerDriver(JDBCDriver);
            JDBCConnection = DriverManager.getConnection ("jdbc:as400://" + serverAddress, userName, password);
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "JDBC connection succeded. Job ident " 
                                                                + ((AS400JDBCConnection)JDBCConnection).getServerJobIdentifier());     
            JDBCSystem = ((AS400JDBCConnection)JDBCConnection).getSystem();            
        } catch (Exception ex) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        ifsTreeModel = new IFSFileTreeModel("/");
        ifsListModel = new IFSFileListModel("/");
        ifsFileTreeRenderer = new IFSFileTreeCellRenderer();                
        
        dbTempConnection = new SqliteDbConnector(new SimpleDateFormat("YYMMddHHmmSS").format(new Date()), true);           
    }

    public IBMiConnector(String serverAddress, boolean useSSL, boolean useJDBC, boolean useGUI, boolean useSockets, boolean useNetSockets, String temporaryLibrary, String userName, String password) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException{
        this(serverAddress, useSSL, useJDBC, useGUI, useSockets, useNetSockets, temporaryLibrary, userName, password, false, "");
    }
    
    public IBMiConnector(String serverAddress, boolean useSSL, String temporaryLibrary, String userName, String password)
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException{
        this(serverAddress, useSSL, true, false, false, false, temporaryLibrary, userName, password);
    }
    
    public IBMiConnector(String serverAddress, boolean useSSL, String temporaryLibrary) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException{
        this(serverAddress, useSSL, temporaryLibrary, "", "");
    }

    public IBMiConnector(String serverAddress, String userName, String password) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException{
        this(serverAddress, false, "QTEMP", userName, password);        
    }
    
    
    public void disconnect() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            IOException, InterruptedException, PropertyVetoException, SQLException, ObjectDoesNotExistException{
        if (!curLib.matches("QTEMP")) {        
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CLROUTQ OUTQ(" + curLib + "/" + DEFAULT_OUTQ_NAME + ")"));
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("DLTOUTQ OUTQ(" + curLib + "/" + DEFAULT_OUTQ_NAME + ")"));
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CLRLIB LIB(" + curLib + ")"));
        }
        if (JDBCStatement != null && !JDBCStatement.isClosed()) JDBCStatement.close();
        if (JDBCConnection  != null && !JDBCConnection.isClosed()) JDBCConnection.close();
        (secure ? secureConnection : insecureConnection).disconnectAllServices();
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Disconnected.");
        dbTempConnection.disconnect();
        dbTempConnection.deleteDatabase();
    }
    
    public String getExceptionDetails(Exception ex) {
        String exceptionDetails = "";
        exceptionDetails += "Exception thrown was: " + ex.getClass().getName() + "\nException details:\n";
        switch (ex.getClass().getName()) {
            case "com.ibm.as400.access.ErrorCompletingRequestException":
                ErrorCompletingRequestException ecreEx = (ErrorCompletingRequestException)ex;
                switch(ecreEx.getReturnCode()) {
                    case ErrorCompletingRequestException.AS400_ERROR:
                        exceptionDetails += "An error has occurred on the AS/400 system.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_POINT_PROCESSING_ERROR:
                        exceptionDetails += "An error occurred while processing the exit point.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_CALL_ERROR:
                        exceptionDetails += "An error occurred with the user exit program call.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_DENIED_REQUEST:
                        exceptionDetails += "The user exit program associated with the server job rejected the request.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_ERROR:
                        exceptionDetails += "The user exit program associated with the server job failed.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_NOT_FOUND:
                        exceptionDetails += "The user exit program associated with the server job could not be found.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_NUMBER_NOT_VALID:
                        exceptionDetails += "The number of user exit programs associated with the server job is not valid.\n";
                        break;
                    case ErrorCompletingRequestException.EXIT_PROGRAM_RESOLVE_ERROR:
                        exceptionDetails += "An error occurred when resolving to the exit program.\n";
                        break;
                    case ErrorCompletingRequestException.LENGTH_NOT_VALID:
                        exceptionDetails += "The AS/400 resource has a length that is not valid or cannot be handled through this interface.\n";
                        break;
                    case ErrorCompletingRequestException.SPOOLED_FILE_NO_MESSAGE_WAITING:
                        exceptionDetails += "The spooled file does not have a message waiting.\n";
                        break;
                    case ErrorCompletingRequestException.UNKNOWN:
                        exceptionDetails += "The exact cause of the failure is not known.\n";
                        break;
                    case ErrorCompletingRequestException.WRITER_JOB_ENDED:
                        exceptionDetails += "The writer job has ended.\n";
                        break;
                }
                exceptionDetails += "\nDetailed message:\n" + ecreEx.getMessage();
                break;
        }
        return exceptionDetails;
    }
    
    public int getCurrentTaskProgress(){
        if (!isActiveTask)
            return -1;
        else
            return currentTaskProgress;
    }
    
    public void cancelCurrentTask(){
        isCancelledTask = true;
    }
    
    public String APIParameterXMLStringGetSVCPGM(String XML) {
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        try{
            DocumentBuilder builder = domFactory.newDocumentBuilder();
            String XMLfilteredText = XML.trim().replaceAll("[\\t\\n\\r]","")
                                            .replaceAll("( )+"," ").replaceAll("> <", "><");            
            Document doc = builder.parse(new InputSource(new StringReader(XMLfilteredText)));

            Element XMLroot = doc.getDocumentElement();
            return XMLroot.getAttribute("SVCPGM");
        }
        catch(Exception ex)
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }        
    }
    
    public DefaultTableModel APIParameterXMLStringToTableModel(String XML){
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        try{
            DocumentBuilder builder = domFactory.newDocumentBuilder();
            String XMLfilteredText = XML.trim().replaceAll("[\\t\\n\\r]","")
                                            .replaceAll("( )+"," ").replaceAll("> <", "><");            
            Document doc = builder.parse(new InputSource(new StringReader(XMLfilteredText)));

            Element XMLroot = doc.getDocumentElement();
            
            NodeList XMLnodeList = XMLroot.getElementsByTagName("Parameter");

            Vector columnNames = new Vector();
            Vector rows = new Vector();
            
            for(int i=0;i<XMLnodeList.getLength();i++)
            {
                Vector newRow = new Vector();
                Node node=XMLnodeList.item(i);
                for (int j=0; j<node.getChildNodes().getLength();j++) {
                    newRow.addElement(node.getChildNodes().item(j).getTextContent());
                    if (i==0 || j > columnNames.size() - 1 ) 
                        columnNames.addElement(node.getChildNodes().item(j).getNodeName());
                }
                rows.addElement(newRow);
            }
            
            DefaultTableModel tableModel = new DefaultTableModel(rows,columnNames);
            return tableModel;
        }
        catch(Exception ex)
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    public String APIParameterTableModelToXMLString(DefaultTableModel tableModel, String serviceProgramName){
        int nRow = tableModel.getRowCount();
        int nCol = tableModel.getColumnCount();
        String strXML = "";
        strXML += "<ParameterGroup SVCPGM=\"" + serviceProgramName +
                    "\">\n";
        for (int i = 0 ; i < nRow ; i++) {
            strXML += "<Parameter>\n ";
            for (int j = 0 ; j < nCol ; j++) {
                strXML += "<"+tableModel.getColumnName(j) + ">" + 
                        (tableModel.getValueAt(i, j)==null ? "" : tableModel.getValueAt(i, j)) 
                        + "</" + tableModel.getColumnName(j) + ">\n";
            }            
            strXML += "</Parameter>\n";
        }
        strXML += "</ParameterGroup>\n";  
        return strXML;
    }
    
    public void exportToBinaryFile(String fileName, byte[] binaryInput){
        System.out.println("Save as file: " + fileName);
        try {              
            prepareFile(fileName);
            FileOutputStream fileOutStream = new FileOutputStream(fileName);
            fileOutStream.write(binaryInput);
            fileOutStream.close();
        } catch (Exception ex) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }
        
    public void exportToXLSX(String fileName, DefaultTableModel tableModel){
        Workbook excelWorkbook = new XSSFWorkbook();
        System.out.println("Save as file: " + fileName);
        try {
            prepareFile(fileName);
            FileOutputStream fileOutStream = new FileOutputStream(fileName);                
            Sheet sheet = excelWorkbook.createSheet(fileName.replaceAll("[:\\\\////]", "."));
            for (int rowNum=0; rowNum <= tableModel.getRowCount(); rowNum++) {
                Row row = sheet.createRow(rowNum);
                for (int colNum=0; colNum < tableModel.getColumnCount(); colNum++) {
                    Cell cell = row.createCell(colNum);
                    if (rowNum>0)
                        cell.setCellValue((tableModel.getValueAt(rowNum-1, colNum) != null ? tableModel.getValueAt(rowNum-1, colNum).toString() : ""));
                    else
                        cell.setCellValue(tableModel.getColumnName(colNum));                            
                }
            }
                excelWorkbook.write(fileOutStream);
                fileOutStream.close();
                
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            }          
    }

    public void exportToXLSX2(String fileName, String tableName) throws SQLException{
        dbTempConnection.exportXLSX(fileName, tableName);
    }
    
    public void exportPhysicalFileToDOCX(String fileName, String QSYSpath) 
            throws AS400Exception, AS400SecurityException, InterruptedException, 
            IOException, PropertyVetoException, SQLException{
        String tableName = getPhysicalFileMemberAsTable2(QSYSpath.replace("%CURLIB%", curLib));
        dbTempConnection.exportDOCX(fileName, tableName);        
    }
    
    public void exportToDOCX(String fileName, String inputText){
        
        System.out.println("Save as file: " + fileName);
        try {
            prepareFile(fileName);
            FileOutputStream fileOutStream = new FileOutputStream(fileName);                
            XWPFDocument wordDocument = new XWPFDocument();   
            String[] textArray = inputText.split("\n");
            for (String textLine : textArray)
            {
                if (textLine.length()==0 || textLine == null) continue;
                XWPFParagraph tmpParagraph = wordDocument.createParagraph();
                XWPFRun tmpRun = tmpParagraph.createRun();   
                tmpRun.setText(textLine);
                tmpRun.setFontSize(8);
                tmpRun.setFontFamily("Courier New");
            }
            wordDocument.write(fileOutStream);
            fileOutStream.close();
        } catch (Exception ex) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }  
    }

    public String getJobLog() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            InterruptedException, IOException, ObjectDoesNotExistException{
        String jobLogText = "";
        JobLog jobLog = currentJob.getJobLog();
        Enumeration jobLogMessages = jobLog.getMessages();      
        while (jobLogMessages.hasMoreElements()){
            QueuedMessage jobLogMessage = (QueuedMessage)jobLogMessages.nextElement();
            jobLogText += jobLogMessage.getText() + "\n\n"+ jobLogMessage.getMessageHelpReplacementandFormat()+"\n\n\n";
        }
        return jobLogText;
    }
    
    public String getJobsList() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException {
        String outputString = "";
        JobList jobList = new JobList((secure ? secureConnection : insecureConnection));
        jobList.addJobSelectionCriteria(JobList.SELECTION_USER_NAME, currentJob.getStringValue(Job.CURRENT_USER));
        jobList.addJobAttributeToSortOn(Job.JOB_DATE, Boolean.FALSE);
        jobList.addJobSelectionCriteria(JobList.SELECTION_JOB_NAME, "QPRTJOB");
        jobList.addJobAttributeToRetrieve(Job.JOB_NUMBER);
        jobList.addJobAttributeToRetrieve(Job.JOB_DATE);
        Enumeration jobListEnum = jobList.getJobs();
        while (jobListEnum.hasMoreElements()) {
            Job curJob = (Job)jobListEnum.nextElement();
            outputString += curJob.getName() + ":" + curJob.getNumber() + ":" + curJob.getDate().toString() + "\n";
        }
        return outputString;
    }

    public String getSpoolFile(String spoolName) 
            throws PropertyVetoException, AS400Exception, 
            AS400SecurityException, ErrorCompletingRequestException, 
            IOException, InterruptedException, RequestNotSupportedException, ObjectDoesNotExistException, SQLException{
                
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CPYSPLF FILE(" + spoolName + ") TOFILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") JOB(" +
                                _getLastPrintJobNumber() + "/" + currentJob.getStringValue(Job.CURRENT_USER) + "/QPRTJOB) SPLNBR(*LAST)"));
        
        String outputString = getPhysicalFileMemberAsText(curLib + "/" + DEFAULT_SPLF_NAME + "");
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("RMVM FILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") MBR(*ALL)"));
        return outputString;
    }

    public void getSpoolFileToDOCX(String fileName, String spoolName) 
            throws PropertyVetoException, AS400Exception, 
            AS400SecurityException, ErrorCompletingRequestException, 
            IOException, InterruptedException, RequestNotSupportedException, ObjectDoesNotExistException, SQLException{
                
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CPYSPLF FILE(" + spoolName + ") TOFILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") JOB(" +
                                _getLastPrintJobNumber() + "/" + currentJob.getStringValue(Job.CURRENT_USER) + "/QPRTJOB) SPLNBR(*LAST)"));
        
        this.exportPhysicalFileToDOCX(fileName, curLib + "/" + DEFAULT_SPLF_NAME + "");
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("RMVM FILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") MBR(*ALL)"));
    }
    
    
    public void printSpoolFileList() 
            throws PropertyVetoException, AS400Exception, AS400SecurityException, 
            ConnectionDroppedException, ErrorCompletingRequestException, 
            InterruptedException, IOException, RequestNotSupportedException{
            
            SpooledFileList splfList = new SpooledFileList((secure ? secureConnection : insecureConnection));
            splfList.setUserFilter((secure ? secureConnection : insecureConnection).getUserId());          
            splfList.setQueueFilter("/QSYS.LIB/" + curLib + ".LIB/" + DEFAULT_OUTQ_NAME + ".OUTQ");

            splfList.openAsynchronously();
            splfList.waitForListToComplete();

            Enumeration spoolfilesListEnum = splfList.getObjects();

            
            // output the name of all objects on the list
            while( spoolfilesListEnum.hasMoreElements() )
            {
                SpooledFile splf = (SpooledFile)spoolfilesListEnum.nextElement();
                if (splf != null)
                {
                    System.out.println(" spooled file = " + splf.getStringAttribute(SpooledFile.ATTR_SPOOLFILE) + ":" +
                            splf.getIntegerAttribute(SpooledFile.ATTR_SPLFNUM).toString());
                }
            }
            splfList.close();
    }  

    public String getPhysicalFileMemberAsText(String QSYSpath)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {        
        String outputString = "";
        DefaultTableModel tableModel = getPhysicalFileMemberAsTable(QSYSpath.replace("%CURLIB%", curLib));
        int nRow = tableModel.getRowCount();
        int nCol = tableModel.getColumnCount();
        for (int i=0; i<nRow; i++)
        {
            for (int j=0; j<nCol; j++)
                outputString += tableModel.getValueAt(i, j);
            outputString += "\n";
        }
        return outputString;
    }
    
    public DefaultTableModel getPhysicalFileMemberAsTable(String QSYSpath)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {
        String[] pathDetails = QSYSpath.split("/");
        if (pathDetails.length != 2) return null;
        return getPhysicalFileMemberAsTable(pathDetails[0], pathDetails[1], "%FIRST%", 0, -1);
    }
    
    public DefaultTableModel getPhysicalFileMemberAsTable(String libName, String fileName)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {
        return getPhysicalFileMemberAsTable(libName, fileName, "%FIRST%", 1, -1);        
    }
    
    public DefaultTableModel getPhysicalFileMemberAsTable(String libName, String fileName, String memberName)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {
        return getPhysicalFileMemberAsTable(libName, fileName, "%FIRST%", 1, -1);        
    }
    
    public DefaultTableModel getPhysicalFileMemberAsTable(String libName, String fileName, String memberName, int rowFrom, int rowTo) 
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {
        
        QSYSObjectPathName filePath = new QSYSObjectPathName(libName.replace("%CURLIB%", curLib), fileName, memberName, "MBR");
        SequentialFile seqFile = new SequentialFile(secure ? secureConnection : insecureConnection, filePath.getPath());
     
        AS400FileRecordDescription recordDesc = new AS400FileRecordDescription(secure ? secureConnection : insecureConnection, filePath.getPath());        
        RecordFormat format = recordDesc.retrieveRecordFormat()[0];

        seqFile.setRecordFormat(format);
        
        seqFile.open(SequentialFile.READ_ONLY, 10, SequentialFile.COMMIT_LOCK_LEVEL_NONE);
        
        Record dataRec = null;
        
        Vector columnNames = new Vector();
        Vector rows = new Vector();
        
        columnNames.addElement("#");
        String[] fieldNames = format.getFieldNames();
        FieldDescription[] fieldDesc = format.getFieldDescriptions();
        for (int fieldIterator=0; fieldIterator<fieldNames.length; fieldIterator++)
            columnNames.addElement((fieldDesc[fieldIterator].getTEXT() == null ? 
                    fieldNames[fieldIterator] : 
                    fieldDesc[fieldIterator].getTEXT() + " (" + fieldNames[fieldIterator] + ")"));       
        
        int curRow = rowFrom;
        if (curRow == 0)
            curRow = 1;
        
        int maxRow = rowTo;
        if (maxRow >=0 && maxRow < curRow)
            maxRow = curRow;
        
        seqFile.positionCursor(curRow);
        while (((dataRec = seqFile.readNext()) != null) && (curRow <= maxRow || maxRow == -1)) {
            Vector newRow = new Vector();
            newRow.addElement(String.valueOf(curRow));
            for (int fieldNum=0; fieldNum<dataRec.getNumberOfFields();fieldNum++) {                
                newRow.addElement(dataRec.getField(fieldNum).toString());
            }
            rows.addElement(newRow);                
            curRow += 1;
        }
        seqFile.close();
        return new DefaultTableModel(rows, columnNames);
    }

    public String getPhysicalFileMemberAsTable2(String QSYSpath)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException, SQLException {
        String[] pathDetails = QSYSpath.split("/");
        if (pathDetails.length != 2) return null;
        return getPhysicalFileMemberAsTable2(pathDetails[0], pathDetails[1], "%FIRST%", 0, -1);
    }
    
    public String getPhysicalFileMemberAsTable2(String libName, String fileName)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException, SQLException {
        return getPhysicalFileMemberAsTable2(libName, fileName, "%FIRST%", 1, -1);        
    }
    
    public String getPhysicalFileMemberAsTable2(String libName, String fileName, String memberName)
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException, SQLException {
        return getPhysicalFileMemberAsTable2(libName, fileName, "%FIRST%", 1, -1);        
    }
    
    
    public String getPhysicalFileMemberAsTable2(String libName, String fileName, String memberName, int rowFrom, int rowTo) 
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException, SQLException {
        
        String fileTableName = "";
        
        QSYSObjectPathName filePath = new QSYSObjectPathName(libName.replace("%CURLIB%", curLib), fileName, memberName, "MBR");
        SequentialFile seqFile = new SequentialFile(secure ? secureConnection : insecureConnection, filePath.getPath());
     
        AS400FileRecordDescription recordDesc = new AS400FileRecordDescription(secure ? secureConnection : insecureConnection, filePath.getPath());        
        RecordFormat format = recordDesc.retrieveRecordFormat()[0];

        
        seqFile.setRecordFormat(format);
        
        seqFile.open(SequentialFile.READ_ONLY, 10, SequentialFile.COMMIT_LOCK_LEVEL_NONE);
        
        Record dataRec = null;
        
        Vector columnNames = new Vector();
        Vector rows = new Vector();
        
        columnNames.addElement("#");
        String[] fieldNames = format.getFieldNames();
        FieldDescription[] fieldDesc = format.getFieldDescriptions();
        for (int fieldIterator=0; fieldIterator<fieldNames.length; fieldIterator++)
            columnNames.addElement((fieldDesc[fieldIterator].getTEXT() == null ? 
                    fieldNames[fieldIterator] : 
                    fieldDesc[fieldIterator].getTEXT() + " (" + fieldNames[fieldIterator] + ")"));       
        
        
        fileTableName = dbTempConnection.createTempTable("fileTable", columnNames.size());
        dbTempConnection.insertrow(fileTableName, columnNames);

        int curRow = rowFrom;
        if (curRow == 0)
            curRow = 1;
        
        int maxRow = rowTo;
        if (maxRow >=0 && maxRow < curRow)
            maxRow = curRow;
        
        seqFile.positionCursor(curRow);
        while (((dataRec = seqFile.readNext()) != null) && (curRow <= maxRow || maxRow == -1)) {
            Vector newRow = new Vector();
            newRow.addElement(String.valueOf(curRow));
            for (int fieldNum=0; fieldNum<dataRec.getNumberOfFields();fieldNum++) {                
                newRow.addElement(dataRec.getField(fieldNum).toString());
            }
            dbTempConnection.insertrow(fileTableName, newRow);
            curRow += 1;
        }
        seqFile.close();
        return fileTableName;
    }
        
    public void updatePhysicalFileMemberRecord(String libName, String fileName, String memberName, int recordNumber, int colNumber, Object newValue) 
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {
        
        QSYSObjectPathName filePath = new QSYSObjectPathName(libName.replace("%CURLIB%", curLib), fileName, memberName, "MBR");
        SequentialFile seqFile = new SequentialFile(secure ? secureConnection : insecureConnection, filePath.getPath());
     
        AS400FileRecordDescription recordDesc = new AS400FileRecordDescription(secure ? secureConnection : insecureConnection, filePath.getPath());        
        RecordFormat[] format = recordDesc.retrieveRecordFormat();

        seqFile.setRecordFormat(format[0]);
        
        seqFile.open(SequentialFile.READ_WRITE, 10, SequentialFile.COMMIT_LOCK_LEVEL_CHANGE);
        
        seqFile.positionCursor(recordNumber);
        
        Record dataRec = seqFile.read();
        dataRec.setField(colNumber, newValue);
        seqFile.update(dataRec);
        seqFile.commit();
        seqFile.close();
    }
    
    
    public void exportPhysicalFileMemberAsXLSX(String libName, String fileName, String memberName, String outputPath) 
            throws AS400Exception, AS400SecurityException, 
            InterruptedException, IOException, PropertyVetoException {

        QSYSObjectPathName filePath = new QSYSObjectPathName(libName.replace("%CURLIB%", curLib), fileName, memberName, "MBR");
        SequentialFile seqFile = new SequentialFile(secure ? secureConnection : insecureConnection, filePath.getPath());
     
        AS400FileRecordDescription recordDesc = new AS400FileRecordDescription(secure ? secureConnection : insecureConnection, filePath.getPath());        
        RecordFormat[] format = recordDesc.retrieveRecordFormat();

        seqFile.setRecordFormat(format[0]);
        
        seqFile.open(SequentialFile.READ_ONLY, 10, SequentialFile.COMMIT_LOCK_LEVEL_NONE);
        
        Record dataRec = null;
        
        Vector columnNames = new Vector();
        Vector rows = new Vector();
        
        String[] fieldNames = format[0].getFieldNames();
        FieldDescription[] fieldDesc = format[0].getFieldDescriptions();
        for (int fieldIterator=0; fieldIterator<fieldNames.length; fieldIterator++)
            columnNames.addElement((fieldDesc[fieldIterator].getTEXT() == null ? 
                    fieldNames[fieldIterator] : 
                    fieldDesc[fieldIterator].getTEXT() + " (" + fieldNames[fieldIterator] + ")"));       
                
        while ((dataRec = seqFile.readNext()) != null) {
            Vector newRow = new Vector();
            for (int fieldNum=0; fieldNum<dataRec.getNumberOfFields();fieldNum++) {                
                newRow.addElement(dataRec.getField(fieldNum).toString());
            }
            rows.addElement(newRow);                
        }
        
    
        }    

    
    public byte[] getIFSBinaryFile(String filePath) 
            throws AS400SecurityException, IOException {
        IFSFileInputStream ifsFile = 
                new IFSFileInputStream(secure ? secureConnection : insecureConnection, filePath);
        int bytesAvailable = ifsFile.available();
        byte[] outputArray = new byte[bytesAvailable];      
        byte[] readData = new byte[10240];
        for (int i = 0; i < bytesAvailable; i += 10240) {
            ifsFile.read(readData);
            System.arraycopy(readData, 0, outputArray, i, readData.length);
        }
        return outputArray;
    }

    public String getIFSTextFile(String filePath) 
            throws AS400SecurityException, IOException {
        
        String outputString = "";
        String readLine;        
        
        IFSFile ifsFile = 
                new IFSFile(secure ? secureConnection : insecureConnection, filePath);
        BufferedReader fileReader = new BufferedReader(new IFSFileReader(ifsFile));
        
        while ((readLine = fileReader.readLine()) != null)
            outputString += readLine;
        
        fileReader.close();
        
        return outputString;
    }    
    
    public String runCLCommand(String commandString) 
            throws AS400SecurityException, ErrorCompletingRequestException, 
                    IOException, InterruptedException, PropertyVetoException, SQLException, ObjectDoesNotExistException {
        return _runCLCommand(commandString, CL_COMMAND_EXEC_PLAIN/*CL_COMMAND_EXEC_QSHELL*/);
    }
    
    public String runCLCommand(String commandString, int executionType) 
            throws AS400SecurityException, ErrorCompletingRequestException, 
                    IOException, InterruptedException, PropertyVetoException, SQLException, ObjectDoesNotExistException {
        return _runCLCommand(commandString, executionType);
    }

    public String _runCLCommand(String commandString, int executionType) 
            throws AS400SecurityException, ErrorCompletingRequestException, 
                    IOException, InterruptedException, PropertyVetoException, SQLException, ObjectDoesNotExistException {
       
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        String commandToRun = commandString.replace("%CURLIB%", curLib);
        
        switch (executionType) {
            case CL_COMMAND_EXEC_JDBC:  //CL using JDBC
                if (JDBCConnection == null ) return null;
                
                String sqlCall =  "CALL QSYS.QCMDEXC('" + commandToRun + "', " 
                + prepareAPILengthString(commandToRun.length()) + ")";
                CallableStatement JDBCCallStatement = JDBCConnection.prepareCall(sqlCall);
                ResultSet JDBCResultSet;
                if (JDBCCallStatement.execute()) {
                    JDBCResultSet = JDBCCallStatement.getResultSet();
                    return JDBCResultSet.toString();   
                }
                return String.valueOf(JDBCCallStatement.getUpdateCount());
            case CL_COMMAND_EXEC_QSHELL:
                ProgramCall qp2shell = new ProgramCall(secure ? secureConnection : insecureConnection);        
                ProgramParameter[] qp2shellParms = new ProgramParameter[3];

                
                AS400Text char22Converter = new AS400Text(22);
                AS400Text char3Converter = new AS400Text(3);
                AS400Text charConverter = new AS400Text(commandToRun.length() + 10);

                qp2shellParms[0] = new ProgramParameter(char22Converter.toBytes("/QOpenSys/usr/bin/csh\0"));
                qp2shellParms[1] = new ProgramParameter(char3Converter.toBytes("-c\0"));
                qp2shellParms[2] = new ProgramParameter(charConverter.toBytes("system \"" + commandToRun + "\"\0"));
                qp2shell.setProgram("/qsys.lib/qp2shell.pgm", qp2shellParms);

                if (!qp2shell.run())
                {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Wywalilo sie");
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qp2shell.getMessageList()));
                    return null;
                }    
                return _stringFromAS400Message(qp2shell.getMessageList());
            case CL_COMMAND_EXEC_PLAIN: //using regular CL command call
            default:
                CommandCall commandRun = new CommandCall(secure ? secureConnection : insecureConnection);
                commandRun.setThreadSafe(false);
                commandRun.run(commandToRun);
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Job " + commandString + " was executed. Job number " + commandRun.getServerJob().getNumber().toString());
                return _stringFromAS400Message(commandRun.getMessageList());
        }        
    }   
    public DefaultTableModel getAllAuthorisationLists() 
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        return getAuthoritiesForObjects(ObjectList.ALL, ObjectList.ALL, "*AUTL");
    }
    
    public DefaultTableModel getAllLibraries() 
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        return getAuthoritiesForObjects(ObjectList.ALL, ObjectList.ALL, "*LIB");
    }
    
    public DefaultListModel getEscalationUsers()
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException, ExecutionException{
    
        while (isActiveTask)
            Thread.sleep(1);
        
        isActiveTask = true;
        currentTaskProgress = 0;
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, Thread.currentThread().getName());
        DefaultListModel userListModel = new DefaultListModel();

        ObjectList objectList = new ObjectList(secure ? secureConnection : insecureConnection, 
                                                "QSYS", "*ALL", "*USRPRF");

        Enumeration objectsEnumeration = objectList.getObjects();

        int objectCounter = 0;

        List userList = new ArrayList();
        userList = Collections.list(objectsEnumeration);
        int maxObjects = userList.size();

        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Query running. All objects: {0}", String.valueOf(maxObjects));

        for (Object curObject : userList) {
            if (isCancelledTask){
                isCancelledTask = false;
                isActiveTask = false;
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Task cancelled");
                return null;
            }
            
            ObjectDescription currentObject = (ObjectDescription)curObject;
            try {                
                String description = currentObject.getValueAsString(ObjectDescription.TEXT_DESCRIPTION);
                userListModel.addElement(currentObject.getName());                
            } catch (Exception ex) {                
            }
            currentTaskProgress = (int)(100.0f * objectCounter/maxObjects);
            objectCounter++;
        }
        isActiveTask = false;
        return userListModel;
    }
    
    public DefaultTableModel getObjectList(String objectName, String libraryName, String objectType)
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        return getObjectList(objectName, libraryName, objectType, false);
    }
    
    public DefaultTableModel getObjectList(String objectName, String libraryName, 
                                            String objectType, boolean showAuthorizedOnly)
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
                
        class objectListThreadClass implements Runnable {
            private DefaultTableModel tableModel; 
            private ObjectDescription objectDesc;
            private boolean showAuthOnly;
            
            public objectListThreadClass(DefaultTableModel tblModel, ObjectDescription objDesc, boolean shwAuthOnly) {
                tableModel = tblModel;
                objectDesc = objDesc;
                showAuthOnly = shwAuthOnly;
            }

            public void run(){
                objectListCurThreads++;
                Vector newRow = new Vector();
                boolean isAuthorized = true;
                try {
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.NAME));
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.LIBRARY));
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.TYPE));
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.TEXT_DESCRIPTION));
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.CREATION_DATE));
                    newRow.addElement(objectDesc.getValueAsString(ObjectDescription.CHANGE_DATE)); 
                } catch (Exception ex) {
                    newRow.addElement("Not authorized");
                    isAuthorized = false;
                }
                if (isAuthorized || (!isAuthorized && !showAuthOnly))
                    try {
                        tableModel.addRow(newRow);
                    } catch (Exception ex) {
                        Logger.getAnonymousLogger().log(Level.INFO, "Error while adding row");
                    }
                objectListCurThreads--;
            }
        }
        
        ObjectList objectList = new ObjectList(secure ? secureConnection : insecureConnection, 
                                                libraryName, objectName, objectType);
        
        Enumeration objectsEnumeration = objectList.getObjects();

        DefaultTableModel objectListTableModel = new DefaultTableModel();        
        objectListTableModel.addColumn("Name");
        objectListTableModel.addColumn("Library");
        objectListTableModel.addColumn("Type");
        objectListTableModel.addColumn("Description");
        objectListTableModel.addColumn("Creation date");
        objectListTableModel.addColumn("Change date");

        int objectCounter = 0;
        while (objectsEnumeration.hasMoreElements()) {
            
            ObjectDescription currentObject = (ObjectDescription)objectsEnumeration.nextElement();

            Runnable objectListRunnable = new objectListThreadClass(objectListTableModel, currentObject, showAuthorizedOnly);
            while (objectListCurThreads > MAX_THREADS) Thread.sleep(SLEEP_TIME);
            new Thread(objectListRunnable).start();
            objectCounter++;
        }

        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Query running. Objects counted: {0}", String.valueOf(objectCounter));
        
        int sleepCounter = 0;
        while (objectListCurThreads > 0 && sleepCounter < MAX_SLEEP) 
        {
            sleepCounter += SLEEP_TIME;
            Thread.sleep(SLEEP_TIME);                
        }
    
        return objectListTableModel;

    }    
    
    public DefaultTableModel getAllQSYSCommands() 
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        return getAuthoritiesForObjects("QSYS", ObjectList.ALL, "*CMD");
    }

    public DefaultTableModel getAuthoritiesForIFSFilesInFolder(String path) 
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        IFSJavaFile root = new IFSJavaFile(secure ? secureConnection : insecureConnection, path);
        String[] fileList;
        IFSJavaFile[] fileProperties;
                                     
        Vector rows = new Vector();
        Vector columnNames = new Vector();        
        
        columnNames.addElement("Basic access rights");
        columnNames.addElement("Last modified");
        columnNames.addElement("Name");
        
        try {
            fileList = root.list();
        } catch (Exception ex) {
            Vector newRow = new Vector();
            newRow.addElement("");
            rows.addElement(newRow);
            return new DefaultTableModel(rows, columnNames);
        }
        
        if (fileList.length == 0) {
            Vector newRow = new Vector();
            newRow.addElement("");
            rows.addElement(newRow);
            return new DefaultTableModel(rows, columnNames);    
        }
        
        fileProperties = new IFSJavaFile[fileList.length];
        
        for (int i=0; i < fileList.length; i++) {
            fileProperties[i] = new IFSJavaFile(secure ? secureConnection : insecureConnection, 
                    path + "/" + fileList[i]);
        }
        
        for (int i=0; i<fileProperties.length; i++) {
            Vector newRow = new Vector();
            String accessRights = (fileProperties[i].isDirectory() ? "d" : " ");
            accessRights += (fileProperties[i].canRead() ? "r" : "-");
            accessRights += (fileProperties[i].canWrite() ? "w" : "-");
            accessRights += (fileProperties[i].canExecute() ? "x" : "-");
            accessRights += (fileProperties[i].isHidden() ? "h" : "");
            
            newRow.addElement(accessRights);
            newRow.addElement(_convertLongTimeToString(fileProperties[i].lastModified()));
            newRow.addElement(fileProperties[i].getName());
            rows.addElement(newRow);
        }
    return new DefaultTableModel(rows, columnNames);
    }
    
    public ResultSet[] runJDBCQuery(String query) 
            throws SQLException {
        return runJDBCQuery(query, 0);
    }
    
    public ResultSet[] runJDBCQuery(String query, int maxRows) 
            throws SQLException {
        if (JDBCConnection == null ) return null;
        
        int[] batchResponses = null;
        String[] queryTable = query.split(";");
        if (queryTable.length == 0) return null;
        
        JDBCStatement = JDBCConnection.createStatement();
        JDBCStatement.setMaxRows(maxRows);
        
        ResultSet[] resultSet = new ResultSet[queryTable.length];
        
        int curResult = 0;
        for (String batchQuery : queryTable)
            if (batchQuery.length()>0)      
                try {            
                    if (JDBCStatement.execute(batchQuery))
                        resultSet[curResult++] = JDBCStatement.getResultSet();
                } catch (Exception ex) {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);                    
                }
        return resultSet;
    }
    
    public DefaultTableModel getAuthoritiesForObjects(String libraryName, String objectName, String objectType) 
            throws AS400Exception, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException, RequestNotSupportedException{
        ObjectList objectList = new ObjectList(secure ? secureConnection : insecureConnection, 
                libraryName, objectName, objectType);
        Enumeration objectsEnumeration = objectList.getObjects();

        Vector rows = new Vector();
        Vector columnNames = new Vector();
        
        columnNames.addElement("Path");
        columnNames.addElement("Owner");
        columnNames.addElement("Authorisation list");
        columnNames.addElement("User");
        columnNames.addElement("Authorisations obtained from authorisation list");
        columnNames.addElement("User can manage authorisation list");                
        columnNames.addElement("Object permissions");
        columnNames.addElement("Object permissions - Add");
        columnNames.addElement("Object permissions - Alter");
        columnNames.addElement("Object permissions - Delete");
        columnNames.addElement("Object permissions - Execute");
        columnNames.addElement("Object permissions - Existence");
        columnNames.addElement("Object permissions - Management");
        columnNames.addElement("Object permissions - Operational");
        columnNames.addElement("Object permissions - Read");
        columnNames.addElement("Object permissions - Reference");
        columnNames.addElement("Object permissions - Update");
        columnNames.addElement("Data permissions");
        columnNames.addElement("Root permissions");
        columnNames.addElement("Root permissions - Alter");
        columnNames.addElement("Root permissions - Existence");
        columnNames.addElement("Root permissions - Management");
        columnNames.addElement("Root permissions - Reference");

        ObjectDescription currentObject = null;
        Permission objectPermissionsList = null;
        
        while (objectsEnumeration.hasMoreElements()) {
            currentObject = (ObjectDescription)objectsEnumeration.nextElement();
            objectPermissionsList = new Permission(secure ? secureConnection : insecureConnection, 
                    (currentObject.getPath().equals("/QSYS.LIB/QSYS.LIB") ? "/QSYS.LIB" : currentObject.getPath()));
            Enumeration objectPermissions = objectPermissionsList.getUserPermissions();
            while (objectPermissions.hasMoreElements()) {
                Object currentPermissionObject = objectPermissions.nextElement();
                UserPermission currentPermUserPerm = (UserPermission)currentPermissionObject;
                Vector newRow = new Vector();
                newRow.addElement(objectPermissionsList.getObjectPath());
                newRow.addElement(objectPermissionsList.getOwner());
                newRow.addElement(objectPermissionsList.getAuthorizationList());
                newRow.addElement(currentPermUserPerm.getUserID());
                newRow.addElement(currentPermUserPerm.isFromAuthorizationList());
                newRow.addElement(currentPermUserPerm.isAuthorizationListManagement());
                try {
                    QSYSPermission currentPermQSYSPerm = (QSYSPermission)currentPermissionObject;
                    newRow.addElement(currentPermQSYSPerm.getObjectAuthority());
                    newRow.addElement(currentPermQSYSPerm.isAdd());
                    newRow.addElement(currentPermQSYSPerm.isAlter());
                    newRow.addElement(currentPermQSYSPerm.isDelete());
                    newRow.addElement(currentPermQSYSPerm.isExecute());
                    newRow.addElement(currentPermQSYSPerm.isExistence());
                    newRow.addElement(currentPermQSYSPerm.isManagement());
                    newRow.addElement(currentPermQSYSPerm.isOperational());
                    newRow.addElement(currentPermQSYSPerm.isRead());
                    newRow.addElement(currentPermQSYSPerm.isReference());
                    newRow.addElement(currentPermQSYSPerm.isUpdate());
                } catch (Exception ex) {
                    newRow.addElement("n/a");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                }
                try {
                    DLOPermission currentPermDLOPerm = (DLOPermission)currentPermissionObject;
                    newRow.addElement(currentPermDLOPerm.getDataAuthority());
                } catch (Exception ex) {
                    newRow.addElement("n/a");
                }
                try {                    
                    RootPermission currentPermRootPerm = (RootPermission)currentPermissionObject;
                    newRow.addElement(currentPermRootPerm.getDataAuthority());
                    newRow.addElement(currentPermRootPerm.isAlter());
                    newRow.addElement(currentPermRootPerm.isExistence());
                    newRow.addElement(currentPermRootPerm.isManagement());
                    newRow.addElement(currentPermRootPerm.isReference());                
                } catch (Exception ex) {
                    newRow.addElement("n/a");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                    newRow.addElement("");
                }
                rows.addElement(newRow);
            }
        }

        return new DefaultTableModel(rows, columnNames);
    }
        
    public DefaultTableModel getAllSystemValues() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
                    ObjectDoesNotExistException, InterruptedException,
                    IOException {

        if (insecureConnection==null && secureConnection==null)
            return null;
                        
        SystemValueList svList = new SystemValueList(secure ? secureConnection : insecureConnection);
        
        Vector list = svList.getGroup(SystemValueList.GROUP_ALL);        
        
        Vector rows = new Vector();
        Vector columnNames = new Vector();
        
        columnNames.addElement("Name");
        columnNames.addElement("Current value");
        
        for (int i=0; i<list.size(); i++){
            Vector newRow = new Vector();
            SystemValue sysVal = (SystemValue)list.elementAt(i);
            newRow.addElement(sysVal.getName());
            try {
                String sysValString;
                switch (sysVal.getType()) {
                    case SystemValueList.TYPE_ARRAY:
                        sysValString = _stringFromArray((String[])sysVal.getValue(), " ");
                        break;
                    case SystemValueList.TYPE_DATE:
                    case SystemValueList.TYPE_DECIMAL:
                    case SystemValueList.TYPE_INTEGER:
                    case SystemValueList.TYPE_STRING:
                        sysValString = sysVal.getValue().toString();
                        break;
                    default:
                        sysValString = "";
                }
                if (sysValString == null) sysValString = "";
                newRow.addElement(sysValString);
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            }
            rows.addElement(newRow);
        }
        
        return new DefaultTableModel(rows, columnNames);
        
    }
    
    public String getEncryptedPassword(String userName) 
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        return getEncryptedPassword(userName, PASSWORD_HASH_FIRSTDES);
    }

    public String setUserPassword(String userName, String password) 
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {

        if (insecureConnection==null && secureConnection==null)
            return null;
        
        if (userName.length() > 10 || password.length() > 10)
            return null;
        
        return runCLCommand("CHGUSRPRF USRPRF(" + userName.trim().toUpperCase() + ") PASSWORD(" + password.trim() + ")");
    }
    
    
    public String getEncryptedPasswordFromHashString(String hashString, int passType){
        
        if (hashString.length()<538) 
            return null;
        
        switch (passType) {
            case PASSWORD_HASH_UNKNOWNHASH:
                return hashString.substring(154,538);
            case PASSWORD_HASH_HMACSHA1MC:
                return hashString.substring(68,108);
            case PASSWORD_HASH_HMACSHA1UC:
                return hashString.substring(108,148);                
            case PASSWORD_HASH_LMHASH:
                return hashString.substring(32,64);
            case PASSWORD_HASH_SECONDDES:
                return hashString.substring(16,32);
            case PASSWORD_HASH_FIRSTDES:
            default: 
                return hashString.substring(0,16);
        }
    }
    
    public byte[] ____getProfileHandleWithoutPasswordJDBC(String userName, int passType)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {  
    
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QSYGETPH.htm?lang=en
         * 
            Required Parameter Group:

            1	User ID                 	Input	Char(10)
            2	Password value                  Input	Char(10) - "*NOPWD, *NOPWDCHK, *NOPWDSTS"
            3	Profile handle                  Output	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        if (JDBCConnection == null ) return null;
                       
        JDBCStatement = JDBCConnection.createStatement();
        try {
            JDBCStatement.execute("CREATE OR REPLACE PROCEDURE J_QSYGETPH (IN USERNAME VARBINARY(10), IN PASSWORD VARBINARY(10), " +
                                  "OUT HANDLE VARBINARY(12)) EXTERNAL NAME QSYS.QSYGETPH LANGUAGE C++ GENERAL");
        } catch (Exception ex) {
            //do nothing, it means that the procedure was already there.
        }

        String userNameAS400 = padTextRight(userName.toUpperCase(), 10);
                
        String passwordAS400;

        switch (passType) {
            case (PASSWORD_TYPE_NOPWDCHK):
                passwordAS400 = "*NOPWDCHK ";
                break;
            case (PASSWORD_TYPE_NOPWDSTS):
                passwordAS400 = "*NOPWDSTS ";
            default:    
            case (PASSWORD_TYPE_NOPWD): 
                passwordAS400 = "*NOPWD    ";
                break;
        }
        
        AS400Text char10Converter = new AS400Text(10);

        String sqlCall =  "CALL J_QSYGETPH(?, ?, ?)";
        CallableStatement JDBCCallStatement = JDBCConnection.prepareCall(sqlCall);
        
        JDBCCallStatement.setBytes(1, userNameAS400.getBytes("cp1047"));
        JDBCCallStatement.setBytes(2, passwordAS400.getBytes("cp1047"));
        JDBCCallStatement.registerOutParameter(3, Types.VARBINARY);
                
        if (JDBCCallStatement.executeUpdate() >= 0) {
            JDBCStatement.execute("DROP PROCEDURE J_QSYGETPH");
            return JDBCCallStatement.getBytes(3);        
        }
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, JDBCCallStatement.getWarnings().toString());
        return null;        
    }
    
    public byte[] getProfileHandleWithoutPassword(String userName, int passType)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (insecureConnection==null && secureConnection==null)
            return null;
               
        ProgramCall qsygetph = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsygetphParms = new ProgramParameter[3];
        
        AS400Text char10Converter = new AS400Text(10);
        
        String userNameAS400 = userName.toUpperCase();
        while (userNameAS400.length() < 10)
            userNameAS400 += " ";
        
        String passwordAS400;
        switch (passType) {
            case (PASSWORD_TYPE_NOPWDCHK):
                passwordAS400 = "*NOPWDCHK ";
                break;
            case (PASSWORD_TYPE_NOPWDSTS):
                passwordAS400 = "*NOPWDSTS ";
            default:    
            case (PASSWORD_TYPE_NOPWD): 
                passwordAS400 = "*NOPWD    ";
                break;
        }

        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QSYGETPH.htm?lang=en
         * 
            Required Parameter Group:

            1	User ID                 	Input	Char(10)
            2	Password value                  Input	Char(10) - "*NOPWD, *NOPWDCHK, *NOPWDSTS"
            3	Profile handle                  Output	Char(12)
            4	Error code                      I/O	Char(*)
         */
              
        qsygetphParms[0] = new ProgramParameter(char10Converter.toBytes(userNameAS400));
        qsygetphParms[1] = new ProgramParameter(char10Converter.toBytes(passwordAS400));
        qsygetphParms[2] = new ProgramParameter(12);
        
        qsygetph.setProgram("/qsys.lib/qsygetph.pgm", qsygetphParms);  
        
        if (!qsygetph.run())
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qsygetph.getMessageList()));
            return null;
        }
        
        return qsygetphParms[2].getOutputData();
    }   

    public byte[] getProfileHandleWithoutPasswordJDBC(String userName, int passType)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (JDBCSystem == null)
            return null;
               
        ProgramCall qsygetph = new ProgramCall(JDBCSystem);        
        ProgramParameter[] qsygetphParms = new ProgramParameter[3];
        
        AS400Text char10Converter = new AS400Text(10);
        
        String userNameAS400 = userName.toUpperCase();
        while (userNameAS400.length() < 10)
            userNameAS400 += " ";
        
        String passwordAS400;
        switch (passType) {
            case (PASSWORD_TYPE_NOPWDCHK):
                passwordAS400 = "*NOPWDCHK ";
                break;
            case (PASSWORD_TYPE_NOPWDSTS):
                passwordAS400 = "*NOPWDSTS ";
            default:    
            case (PASSWORD_TYPE_NOPWD): 
                passwordAS400 = "*NOPWD    ";
                break;
        }

        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QSYGETPH.htm?lang=en
         * 
            Required Parameter Group:

            1	User ID                 	Input	Char(10)
            2	Password value                  Input	Char(10) - "*NOPWD, *NOPWDCHK, *NOPWDSTS"
            3	Profile handle                  Output	Char(12)
            4	Error code                      I/O	Char(*)
         */
              
        qsygetphParms[0] = new ProgramParameter(char10Converter.toBytes(userNameAS400));
        qsygetphParms[1] = new ProgramParameter(char10Converter.toBytes(passwordAS400));
        qsygetphParms[2] = new ProgramParameter(12);
        
        qsygetph.setProgram("/qsys.lib/qsygetph.pgm", qsygetphParms);  
        
        if (!qsygetph.run())
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qsygetph.getMessageList()));
            return null;
        }
        
        return qsygetphParms[2].getOutputData();
    }    
    
    public boolean _____setProfileHandleJDBC(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {  
    
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QWTSETP.htm?lang=en
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        if (JDBCConnection == null) return false;
        
        JDBCStatement = JDBCConnection.createStatement();
        
        try {
            JDBCStatement.execute("CREATE OR REPLACE PROCEDURE J_QWTSETP (IN HANDLE VARBINARY(12)) EXTERNAL NAME QSYS.QWTSETP LANGUAGE C++ GENERAL");
        } catch (Exception ex) {
            //do nothing, the procedure is already there
        }
        
        String sqlCall =  "CALL J_QWTSETP(?)";
        CallableStatement JDBCCallStatement = JDBCConnection.prepareCall(sqlCall);
        
        JDBCCallStatement.setBytes(1, profileHandle);
                
        if (JDBCCallStatement.executeUpdate() >= 0) {
            JDBCStatement.execute("DROP PROCEDURE J_QWTSETP");
            return true;
        }        
        return false;
    }
    
    public boolean setProfileHandle(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        if (profileHandle.length != 12) return false;
        
        ProgramCall qwtsetp = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qwtsetpParms = new ProgramParameter[2];
                
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QWTSETP.htm?lang=en
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        
        
        qwtsetpParms[0] = new ProgramParameter(profileHandle);
        qwtsetpParms[1] = new ProgramParameter(500);
        
        qwtsetp.setProgram("/qsys.lib/qwtsetp.pgm", qwtsetpParms);                
        return qwtsetp.run();              
    }
    
    public boolean setProfileHandleJDBC(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (JDBCSystem == null)
            return false;                     
        
        if (profileHandle.length != 12) return false;
        
        ProgramCall qwtsetp = new ProgramCall(JDBCSystem);        
        ProgramParameter[] qwtsetpParms = new ProgramParameter[2];
                
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_i5_54/apis/QWTSETP.htm?lang=en
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        
        
        qwtsetpParms[0] = new ProgramParameter(profileHandle);
        qwtsetpParms[1] = new ProgramParameter(500);
        
        qwtsetp.setProgram("/qsys.lib/qwtsetp.pgm", qwtsetpParms);                
        return qwtsetp.run();              
    }
    
    public boolean _____releaseProfileHandleJDBC(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {  
    
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_71/apis/QSYRLSPH.htm
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        if (JDBCConnection == null) return false;
        
        JDBCStatement = JDBCConnection.createStatement();
        try {
            JDBCStatement.execute("CREATE OR REPLACE PROCEDURE J_QSYRLSPH (IN HANDLE VARBINARY(12)) EXTERNAL NAME QSYS.QWTSETP LANGUAGE C++ GENERAL");
        } catch (Exception ex) {
            //do nothing, the procedure is already there
        }
        String sqlCall =  "CALL J_QSYRLSPH(?)";
        CallableStatement JDBCCallStatement = JDBCConnection.prepareCall(sqlCall);
        
        JDBCCallStatement.setBytes(1, profileHandle);
                
        if (JDBCCallStatement.executeUpdate() >= 0) {
            JDBCStatement.execute("DROP PROCEDURE J_QSYRLSPH");
            return true;
        }        
        return false;
    }
    
    public boolean releaseProfileHandleJDBC(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
        
        if (JDBCSystem == null)
            return false;                     
                
        if (profileHandle.length != 12) return false;
        
        ProgramCall qsyrlsph = new ProgramCall(JDBCSystem);      
        ProgramParameter[] qsyrlsphParms = new ProgramParameter[2];
                
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_71/apis/QSYRLSPH.htm
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        
        
        qsyrlsphParms[0] = new ProgramParameter(profileHandle);
        qsyrlsphParms[1] = new ProgramParameter(500);
        
        qsyrlsph.setProgram("/qsys.lib/qsyrlsph.pgm", qsyrlsphParms);                
        return qsyrlsph.run();              
    }
    
    public boolean releaseProfileHandle(byte[] profileHandle)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        if (profileHandle.length != 12) return false;
        
        ProgramCall qsyrlsph = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsyrlsphParms = new ProgramParameter[2];
                
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_71/apis/QSYRLSPH.htm
         * 
            Required Parameter Group:

            1	Profile Handle                  Input	Char(12)
            4	Error code                      I/O	Char(*)
         */
        
        
        
        qsyrlsphParms[0] = new ProgramParameter(profileHandle);
        qsyrlsphParms[1] = new ProgramParameter(500);
        
        qsyrlsph.setProgram("/qsys.lib/qsyrlsph.pgm", qsyrlsphParms);                
        return qsyrlsph.run();              
    }

    public byte[] getProfileTokenWithoutPassword(String userName, int passType)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (insecureConnection==null && secureConnection==null)
            return null;
               
        ProgramCall qsygenpt = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsygenptParms = new ProgramParameter[6];
        
        AS400Text char10Converter = new AS400Text(10);
        AS400Text char1Converter = new AS400Text(1);
        AS400Bin4 bin4 = new AS400Bin4();

        String userNameAS400 = userName.toUpperCase();
        while (userNameAS400.length() < 10)
            userNameAS400 += " ";
        
        String passwordAS400;
        switch (passType) {
            case (PASSWORD_TYPE_NOPWDCHK):
                passwordAS400 = "*NOPWDCHK ";
                break;
            case (PASSWORD_TYPE_NOPWDSTS):
                passwordAS400 = "*NOPWDSTS ";
            default:    
            case (PASSWORD_TYPE_NOPWD): 
                passwordAS400 = "*NOPWD    ";
                break;
        }

        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_72/apis/qsygenpt.htm
         * 
            Required Parameter Group:

            1	Profile token           Output	Char(32)
            2	User profile name	Input	Char(10)
            3	User password           Input	Char(*)
            4	Time out interval	Input	Bin(4)
            5	Profile token type	Input	Char(1)
            6	Error code              I/O	Char(*)

              Optional Parameter Group:

            7	Length of user password	Input	Bin(4)
            8	CCSID of user password	Input	Bin(4)
         */
              
        qsygenptParms[0] = new ProgramParameter(32);
        qsygenptParms[1] = new ProgramParameter(char10Converter.toBytes(userNameAS400));
        qsygenptParms[2] = new ProgramParameter(char10Converter.toBytes(passwordAS400));
        qsygenptParms[3] = new ProgramParameter(bin4.toBytes(new Integer(3600)));
        qsygenptParms[4] = new ProgramParameter(char1Converter.toBytes("3"));
        qsygenptParms[5] = new ProgramParameter(500);
        
        qsygenpt.setProgram("/qsys.lib/qsygenpt.pgm", qsygenptParms);  
        
        if (!qsygenpt.run())
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qsygenpt.getMessageList()));
            return null;
        }
        
        return qsygenptParms[0].getOutputData();
    }   
    
    public boolean setProfileToken(byte[] profileToken)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
    
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        if (profileToken.length != 32) return false;
        
        ProgramCall qsysetpt = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsysetptParms = new ProgramParameter[2];
                        
        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_72/apis/qsysetpt.htm
         * 
            Required Parameter Group for QSYSETPT:

            1	Profile token	Input	Char(32)
            2	Error code	I/O	Char(*)
         */
        
        
        
        qsysetptParms[0] = new ProgramParameter(profileToken);
        qsysetptParms[1] = new ProgramParameter(500);
        
        qsysetpt.setProgram("/qsys.lib/qsysetpt.pgm", qsysetptParms);                
        return qsysetpt.run();              
    }

    public boolean releaseProfileToken(byte[] profileToken)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
          
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        if (profileToken.length != 32) return false;
        
        ProgramCall qsyrmvpt = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsyrmvptParms = new ProgramParameter[3];

        AS400Text char10Converter = new AS400Text(10);

        /*
         *  http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_72/apis/QSYRMVPT.htm?lang=en
         * 
            Required Parameter Group:

            1	Remove option	Input	Char(10)
            2	Error code	I/O	Char(*)

            Optional Parameter:

            3	Profile token	Input	Char(32)
        
         */
        
        
        qsyrmvptParms[0] = new ProgramParameter(char10Converter.toBytes("*PRFTKN"));
        qsyrmvptParms[1] = new ProgramParameter(500);
        qsyrmvptParms[2] = new ProgramParameter(profileToken);
        
        qsyrmvpt.setProgram("/qsys.lib/qsyrmvpt.pgm", qsyrmvptParms);                
        return qsyrmvpt.run();              
    }
    
    public boolean escalatePrivilegeWithoutPassword(String userName, int passType)
        throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
               
        if (escalationLevel >=9 ) return false;
        
        if (escalationLevel == 0) {
            userHandles[0] = new byte[12];
            userHandles[0] = getProfileHandleWithoutPassword("*CURRENT", passType);
        }        
        escalationLevel++;
        
        userHandles[escalationLevel] = new byte[12];
        userHandles[escalationLevel] = getProfileHandleWithoutPassword(userName, passType);        
        
        if (setProfileHandle(userHandles[escalationLevel])) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Successfully escalated privileges to user {0}", userName);
            return true;
        }
        
        return false;
    }

    public boolean escalatePrivilegeWithoutPasswordJDBC(String userName, int passType)
        throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {  
               
        if (escalationLevelJDBC >=9 ) return false;
        
        if (escalationLevelJDBC == 0) {
            userHandlesJDBC[0] = new byte[12];
            userHandlesJDBC[0] = getProfileHandleWithoutPasswordJDBC("*CURRENT", passType);
        }        
        escalationLevelJDBC++;
        
        userHandlesJDBC[escalationLevelJDBC] = new byte[12];
        userHandlesJDBC[escalationLevelJDBC] = getProfileHandleWithoutPasswordJDBC(userName, passType);        
        
        if (setProfileHandleJDBC(userHandlesJDBC[escalationLevelJDBC])) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Successfully escalated privileges to user {0}", userName);           
            return true;
        }
        
        return false;
    }
    
    
    public boolean deescalatePrivileges()
        throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {  
        
        if (escalationLevel == 0 ) return false;
                
        if (setProfileHandle(userHandles[escalationLevel-1]))
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Successfully de-escalated privileges to last user");
        boolean result = releaseProfileHandle(userHandles[escalationLevel]);
        userHandles[escalationLevel] = null;
        
        if (escalationLevel == 1) {
            releaseProfileHandle(userHandles[0]);
            userHandles[0] = null;  
        }
        
        escalationLevel--;
        return result;
    }
    
    public boolean deescalatePrivilegesJDBC()
        throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {  
        
        if (escalationLevelJDBC == 0 ) return false;
                
        if (setProfileHandleJDBC(userHandlesJDBC[escalationLevelJDBC-1]))
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Successfully de-escalated privileges to last user");
        boolean result = releaseProfileHandleJDBC(userHandlesJDBC[escalationLevelJDBC]);
        userHandlesJDBC[escalationLevelJDBC] = null;
        
        if (escalationLevelJDBC == 1) {
            releaseProfileHandleJDBC(userHandlesJDBC[0]);
            userHandlesJDBC[0] = null;  
        }
        
        escalationLevelJDBC--;
        return result;
    }
        
    public String getEncryptedPassword(String userName, int passType) 
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        
        String encryptedPwd = "";

        if (insecureConnection==null && secureConnection==null)
            return null;
        
        ProgramCall qsyrupwd = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsyrupwdParms = new ProgramParameter[5];

        AS400Bin4 bin4 = new AS400Bin4();        
        AS400Text char8Converter = new AS400Text(8);
        AS400Text char10Converter = new AS400Text(10);
        
        String userNameAS400 = userName.toUpperCase();
        while (userNameAS400.length() < 10)
            userNameAS400 += " ";

        /*
         *  http://publib.boulder.ibm.com/infocenter/iseries/v5r4/index.jsp?topic=%2Fapis%2Fqsyrupwd.htm
         * 
            Required Parameter Group:

            1	Receiver variable               Output	Char(*) - 2000B
            2	Length of receiver variable	Input	Binary(4) 
            3	Format                          Input	Char(8) - "UPWD0100"
            4	User profile name               Input	Char(10) - userName
            5	Error code                      I/O	Char(*)
         */
        
        qsyrupwdParms[0] = new ProgramParameter(2000);
        qsyrupwdParms[1] = new ProgramParameter(bin4.toBytes(new Integer(2000)));
        qsyrupwdParms[2] = new ProgramParameter(char8Converter.toBytes("UPWD0100"));
        qsyrupwdParms[3] = new ProgramParameter(char10Converter.toBytes(userNameAS400));
        qsyrupwdParms[4] = new ProgramParameter(500);
        
        qsyrupwd.setProgram("/qsys.lib/qsyrupwd.pgm", qsyrupwdParms);
                
        if (!qsyrupwd.run())
        {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qsyrupwd.getMessageList()));
            return null;
        }
        
        byte[] receiverVariable = qsyrupwdParms[0].getOutputData();
        
        /*
         * 
         * UPWD0100 Format

            Offset	Type            Field
            Dec	Hex
            0	0	BINARY(4)	Bytes returned
            4	4	BINARY(4)	Bytes available
            8	8	CHAR(10)	User profile name
            18	12	CHAR(*)         Encrypted user password data
         * 
         */
        
        AS400Text char500Converter = new AS400Text(500);

        AS400DataType[] dataTypeArray = new AS400DataType[4];
        dataTypeArray[0] = bin4;
        dataTypeArray[1] = bin4;
        dataTypeArray[2] = char10Converter;
        dataTypeArray[3] = char500Converter;
        AS400Structure returnedDataConverter = new AS400Structure(dataTypeArray);

        Object[] qsyrupwdInfo = (Object[]) returnedDataConverter.toObject(receiverVariable, 0);
        
        switch (passType) {
            case PASSWORD_HASH_ALLDATA: // All data
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(2,540);            
            case PASSWORD_HASH_UNKNOWNHASH: // Unknown (hash?) data
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(156,540);
            case PASSWORD_HASH_HMACSHA1UC: // HMAC-SHA1 password (mixed case)
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(70,110);
            case PASSWORD_HASH_HMACSHA1MC: // HMAC-SHA1 password (uppercase)
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(110,150);
            case PASSWORD_HASH_LMHASH: // LM hash
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(34,66);
            case PASSWORD_HASH_SECONDDES: // Second DES password
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(18,34);
            case PASSWORD_HASH_FIRSTDES: // First DES password
            default: 
                return _hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(2,18);
        }        
    }
    
    public Enumeration getAllUsers() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            InterruptedException, IOException, ObjectDoesNotExistException, 
            RequestNotSupportedException{

        if (insecureConnection==null && secureConnection==null)
            return null;    
        
        UserList userList = new UserList(secure ? secureConnection : insecureConnection);
        
        return userList.getUsers();        
        
    }    
    
    public void getJohnPasswordsLM(String fileName) throws IOException
    {
        getJohnPasswords(PASSWORD_HASH_LMHASH, fileName);
    }

    public void getJohnPasswordsSHAUpperCase(String fileName) throws IOException
    {
        getJohnPasswords(PASSWORD_HASH_HMACSHA1UC, fileName);
    }
    
    public void getJohnPasswordsSHAMixedCase(String fileName) throws IOException
    {
        getJohnPasswords(PASSWORD_HASH_HMACSHA1MC, fileName);
    }

    public void getJohnPasswords(int passType, String fileName) throws IOException
    {
        DefaultTableModel pwdMatrix = null;
        User curUser;
        Enumeration allUsers;
        String curPassword;
        File outFile = new File(fileName);
        
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter(outFile));
        
        try {
            allUsers  = getAllUsers();
            while (allUsers.hasMoreElements())
            {
                curUser = (User)allUsers.nextElement();
                curPassword = getEncryptedPassword(curUser.getName(), passType);
                fileWriter.write(curUser.getName() + ":$as400ssha1$" + curPassword + "$" + curUser.getName() + "\n");
            }           
        } catch (Exception ex) {
            return;
        }

        fileWriter.close();                
    }
    
    public DefaultTableModel getAuthorisationMatrix()
    {
        DefaultTableModel authMatrix = null;
        
        Vector columnNames = new Vector();
        Vector rows = new Vector();
        
        User curUser;
        User curGroup;
        Enumeration allUsers;
        Enumeration allGroups;
        LinkedHashSet<String> allGroupsHashSet = new LinkedHashSet<>();
        LinkedHashSet<String> curGroupsHashSet = new LinkedHashSet<>();
        
        try {
           allUsers  = getAllUsers();
           allGroups = getAllUsers();
        } catch (Exception ex) {
            return null;
        }
        
        columnNames.addElement("User name");
        columnNames.addElement("Description");
        columnNames.addElement("Is a group profile?");
        columnNames.addElement("User class");
        columnNames.addElement("Status");
        columnNames.addElement("User expiration interval");
        columnNames.addElement("User expiration date");
        columnNames.addElement("User expiration action");
        columnNames.addElement("User encrypted password (DES-1 hash 1)");
        columnNames.addElement("User encrypted password (DES-1 hash 2)");
        columnNames.addElement("User encrypted password (LM Hash)");
        columnNames.addElement("User encrypted password (SHA-1 hash - mixed case)");
        columnNames.addElement("User encrypted password (SHA-1 hash - uppercase)");
        columnNames.addElement("User encrypted password (unknown hash)");
        columnNames.addElement("Is password expired?");
        columnNames.addElement("Is password *NONE?");
        columnNames.addElement("Are certificates assigned?");
        columnNames.addElement("Password last change date");
        columnNames.addElement("Previous sign-on date");
        columnNames.addElement("Password expiration interval");
        columnNames.addElement("Password expiration date");
        columnNames.addElement("ALLOBJ");
        columnNames.addElement("AUDIT");
        columnNames.addElement("SECADM");
        columnNames.addElement("JOBCTL");
        columnNames.addElement("SPLCTL");
        columnNames.addElement("SAVSYS");
        columnNames.addElement("SERVICE");
        columnNames.addElement("IOSYSCFG");
        columnNames.addElement("Limited capabilities?");
        columnNames.addElement("Limited device sessions?");
        columnNames.addElement("Group profile name");
        columnNames.addElement("Supplemental groups");
        columnNames.addElement("Initial menu");
        columnNames.addElement("Initial program");
        columnNames.addElement("Attention program");
        columnNames.addElement("Current library");
        columnNames.addElement("Home directory");
        columnNames.addElement("Job description");
        columnNames.addElement("Message queue");
        columnNames.addElement("Output queue");
        columnNames.addElement("Print device");
        columnNames.addElement("User action auditing level");
        columnNames.addElement("User object auditing level");
        
        
        while (allGroups.hasMoreElements())
        {
            curGroup = (User)allGroups.nextElement();
            if (curGroup.getGroupID() != 0) {
                String curGroupName = curGroup.getUserProfileName();
                allGroupsHashSet.add(curGroupName);
                columnNames.addElement(curGroupName);
            }
        }
        
        while (allUsers.hasMoreElements())
        {
            curUser = (User)allUsers.nextElement();
            Vector newRow = new Vector();
            //name
            newRow.addElement(curUser.getName().toString());
            //description
            newRow.addElement(curUser.getDescription().toString());
            //isgroup
            newRow.addElement((curUser.getGroupID()!=0 ? "true" : "false"));
            //usrcls
            newRow.addElement(curUser.getUserClassName().toString());
            //status
            newRow.addElement(curUser.getStatus().toString());
            //expitv
            newRow.addElement(String.valueOf(curUser.getUserExpirationInterval()));
            //expdate
            newRow.addElement((curUser.getUserExpirationDate() == null ? "" : curUser.getUserExpirationDate().toString()));
            //expaction
            newRow.addElement(curUser.getUserExpirationAction() == null ? "" : curUser.getUserExpirationAction().toString());
            //password
            try {
                String encryptedPassword = getEncryptedPassword(curUser.getName(), 5);
                
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_FIRSTDES));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_SECONDDES));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_LMHASH));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_HMACSHA1MC));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_HMACSHA1UC));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_UNKNOWNHASH));
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
                return null;
            }
            //pwdexpired
            newRow.addElement((curUser.isPasswordSetExpire() ? "true" : "false"));
            //pwdnone
            newRow.addElement((curUser.isNoPassword() ? "true" : "false"));
            //certs
            newRow.addElement((curUser.isWithDigitalCertificates() ? "true" : "false"));
            //pwdlastchg
            newRow.addElement(curUser.getPasswordLastChangedDate() == null ? "" : curUser.getPasswordLastChangedDate().toString());
            //prevsignon
            newRow.addElement(curUser.getPreviousSignedOnDate() == null ? "" : curUser.getPreviousSignedOnDate().toString());
            //pwdexpitv
            newRow.addElement(String.valueOf(curUser.getPasswordExpirationInterval()));
            //pwdexpdat
            newRow.addElement(curUser.getPasswordExpireDate() == null ? "" : curUser.getPasswordExpireDate().toString());
            //spcaut
            try {                
                //User.SPECIAL_AUTHORITY_ALL_OBJECT            
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_ALL_OBJECT) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_ALL_OBJECT) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_AUDIT
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_AUDIT) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_AUDIT) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_JOB_CONTROL
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_JOB_CONTROL) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_JOB_CONTROL) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SPOOL_CONTROL
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SPOOL_CONTROL) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SPOOL_CONTROL) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SAVE_SYSTEM
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SAVE_SYSTEM) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SAVE_SYSTEM) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SERVICE
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SERVICE) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SERVICE) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION) ? "I" : "X") : ""));
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            }

            //lmtcpb
            newRow.addElement(curUser.getLimitCapabilities().toString());
            //lmtdevssn 
            newRow.addElement(curUser.getLimitDeviceSessions().toString());
            //grppf
            newRow.addElement(curUser.getGroupProfileName().toString());
            //supgrps
            newRow.addElement((curUser.getSupplementalGroups().length == 0 ? "" : _stringFromArray(curUser.getSupplementalGroups(), " ")));
            //inmnu
            newRow.addElement(curUser.getInitialMenu().toString());
            //inpgm
            newRow.addElement(curUser.getInitialProgram().toString());
            //attnpgm
            newRow.addElement(curUser.getAttentionKeyHandlingProgram().toString());            
            //curlib
            newRow.addElement(curUser.getCurrentLibraryName().toString());
            //homedir
            newRow.addElement(curUser.getHomeDirectory().toString());
            //jobd
            newRow.addElement(curUser.getJobDescription().toString());
            //msgq
            newRow.addElement(curUser.getMessageQueue().toString());
            //outq
            newRow.addElement(curUser.getOutputQueue().toString());
            //prtdev
            newRow.addElement(curUser.getPrintDevice().toString());
            //actionaudlvl
            newRow.addElement(curUser.getUserActionAuditLevel() == null ? "" : _stringFromArray(curUser.getUserActionAuditLevel(), " "));
            //objaudval
            newRow.addElement(curUser.getObjectAuditingValue() == null ? "" : curUser.getObjectAuditingValue());

            curGroupsHashSet.clear();

            if (!curUser.getGroupProfileName().equalsIgnoreCase("*NONE"))
                curGroupsHashSet.add(curUser.getGroupProfileName());

            if (curUser.getSupplementalGroupsNumber() > 0)
                curGroupsHashSet.addAll(Arrays.asList(curUser.getSupplementalGroups()));
           
            if (!curGroupsHashSet.isEmpty())
                for (String groupName : allGroupsHashSet) {
                    newRow.addElement((curGroupsHashSet.contains(groupName) ? "X" : ""));
                }
            
            rows.addElement(newRow);
        }

        authMatrix = new DefaultTableModel(rows,columnNames);   
        return authMatrix;
    }

    public String getAuthorisationMatrix2() throws SQLException
    {
        String authMatrixName = "";
        
        Vector columnNames = new Vector();
        Vector rows = new Vector();
        
        User curUser;
        User curGroup;
        Enumeration allUsers;
        Enumeration allGroups;
        LinkedHashSet<String> allGroupsHashSet = new LinkedHashSet<>();
        LinkedHashSet<String> curGroupsHashSet = new LinkedHashSet<>();
        
        try {
           allUsers  = getAllUsers();
           allGroups = getAllUsers();
        } catch (Exception ex) {
            return null;
        }
        
        columnNames.addElement("User name");
        columnNames.addElement("Description");
        columnNames.addElement("Is a group profile?");
        columnNames.addElement("User class");
        columnNames.addElement("Status");
        columnNames.addElement("User expiration interval");
        columnNames.addElement("User expiration date");
        columnNames.addElement("User expiration action");
        columnNames.addElement("User encrypted password (DES-1 hash 1)");
        columnNames.addElement("User encrypted password (DES-1 hash 2)");
        columnNames.addElement("User encrypted password (LM Hash)");
        columnNames.addElement("User encrypted password (SHA-1 hash - mixed case)");
        columnNames.addElement("User encrypted password (SHA-1 hash - uppercase)");
        columnNames.addElement("User encrypted password (unknown hash)");
        columnNames.addElement("Is password expired?");
        columnNames.addElement("Is password *NONE?");
        columnNames.addElement("Are certificates assigned?");
        columnNames.addElement("Password last change date");
        columnNames.addElement("Previous sign-on date");
        columnNames.addElement("Password expiration interval");
        columnNames.addElement("Password expiration date");
        columnNames.addElement("ALLOBJ");
        columnNames.addElement("AUDIT");
        columnNames.addElement("SECADM");
        columnNames.addElement("JOBCTL");
        columnNames.addElement("SPLCTL");
        columnNames.addElement("SAVSYS");
        columnNames.addElement("SERVICE");
        columnNames.addElement("IOSYSCFG");
        columnNames.addElement("Limited capabilities?");
        columnNames.addElement("Limited device sessions?");
        columnNames.addElement("Group profile name");
        columnNames.addElement("Supplemental groups");
        columnNames.addElement("Initial menu");
        columnNames.addElement("Initial program");
        columnNames.addElement("Attention program");
        columnNames.addElement("Current library");
        columnNames.addElement("Home directory");
        columnNames.addElement("Job description");
        columnNames.addElement("Message queue");
        columnNames.addElement("Output queue");
        columnNames.addElement("Print device");
        columnNames.addElement("User action auditing level");
        columnNames.addElement("User object auditing level");
                
        
        List groupList = new ArrayList();
        groupList = Collections.list(allGroups);
                
        for (Object currentGroup : groupList)
        {
            curGroup = (User)currentGroup;
            if (curGroup.getGroupID() != 0) {
                String curGroupName = curGroup.getUserProfileName();
                allGroupsHashSet.add(curGroupName);
                columnNames.addElement(curGroupName);
            }
        }
        
        authMatrixName = dbTempConnection.createTempTable("istmatrix", 44 + allGroupsHashSet.size());
        
        
        //the first row contains column names
        dbTempConnection.insertrow(authMatrixName, columnNames);
        
        while (allUsers.hasMoreElements())
        {
            curUser = (User)allUsers.nextElement();
            Vector newRow = new Vector();
            //name
            newRow.addElement(curUser.getName().toString());
            //description
            newRow.addElement(curUser.getDescription().toString());
            //isgroup
            newRow.addElement((curUser.getGroupID()!=0 ? "true" : "false"));
            //usrcls
            newRow.addElement(curUser.getUserClassName().toString());
            //status
            newRow.addElement(curUser.getStatus().toString());
            //expitv
            newRow.addElement(String.valueOf(curUser.getUserExpirationInterval()));
            //expdate
            newRow.addElement((curUser.getUserExpirationDate() == null ? "" : curUser.getUserExpirationDate().toString()));
            //expaction
            newRow.addElement(curUser.getUserExpirationAction() == null ? "" : curUser.getUserExpirationAction().toString());
            //password
            try {
                String encryptedPassword = getEncryptedPassword(curUser.getName(), 5);
                
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_FIRSTDES));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_SECONDDES));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_LMHASH));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_HMACSHA1MC));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_HMACSHA1UC));
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_UNKNOWNHASH));
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
                return null;
            }
            //pwdexpired
            newRow.addElement((curUser.isPasswordSetExpire() ? "true" : "false"));
            //pwdnone
            newRow.addElement((curUser.isNoPassword() ? "true" : "false"));
            //certs
            newRow.addElement((curUser.isWithDigitalCertificates() ? "true" : "false"));
            //pwdlastchg
            newRow.addElement(curUser.getPasswordLastChangedDate() == null ? "" : curUser.getPasswordLastChangedDate().toString());
            //prevsignon
            newRow.addElement(curUser.getPreviousSignedOnDate() == null ? "" : curUser.getPreviousSignedOnDate().toString());
            //pwdexpitv
            newRow.addElement(String.valueOf(curUser.getPasswordExpirationInterval()));
            //pwdexpdat
            newRow.addElement(curUser.getPasswordExpireDate() == null ? "" : curUser.getPasswordExpireDate().toString());
            //spcaut
            try {                
                //User.SPECIAL_AUTHORITY_ALL_OBJECT            
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_ALL_OBJECT) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_ALL_OBJECT) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_AUDIT
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_AUDIT) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_AUDIT) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SECURITY_ADMINISTRATOR) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_JOB_CONTROL
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_JOB_CONTROL) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_JOB_CONTROL) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SPOOL_CONTROL
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SPOOL_CONTROL) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SPOOL_CONTROL) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SAVE_SYSTEM
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SAVE_SYSTEM) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SAVE_SYSTEM) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_SERVICE
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_SERVICE) ?
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_SERVICE) ? "I" : "X") : ""));
                //User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION
                newRow.addElement((curUser.hasSpecialAuthority(User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION) ? 
                                                            (checkUserSpecialAuthority(curUser.getUserProfileName(), User.SPECIAL_AUTHORITY_IO_SYSTEM_CONFIGURATION) ? "I" : "X") : ""));
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            }

            //lmtcpb
            newRow.addElement(curUser.getLimitCapabilities().toString());
            //lmtdevssn 
            newRow.addElement(curUser.getLimitDeviceSessions().toString());
            //grppf
            newRow.addElement(curUser.getGroupProfileName().toString());
            //supgrps
            newRow.addElement((curUser.getSupplementalGroups().length == 0 ? "" : _stringFromArray(curUser.getSupplementalGroups(), " ")));
            //inmnu
            newRow.addElement(curUser.getInitialMenu().toString());
            //inpgm
            newRow.addElement(curUser.getInitialProgram().toString());
            //attnpgm
            newRow.addElement(curUser.getAttentionKeyHandlingProgram().toString());            
            //curlib
            newRow.addElement(curUser.getCurrentLibraryName().toString());
            //homedir
            newRow.addElement(curUser.getHomeDirectory().toString());
            //jobd
            newRow.addElement(curUser.getJobDescription().toString());
            //msgq
            newRow.addElement(curUser.getMessageQueue().toString());
            //outq
            newRow.addElement(curUser.getOutputQueue().toString());
            //prtdev
            newRow.addElement(curUser.getPrintDevice().toString());
            //actionaudlvl
            newRow.addElement(curUser.getUserActionAuditLevel() == null ? "" : _stringFromArray(curUser.getUserActionAuditLevel(), " "));
            //objaudval
            newRow.addElement(curUser.getObjectAuditingValue() == null ? "" : curUser.getObjectAuditingValue());

            curGroupsHashSet.clear();

            if (!curUser.getGroupProfileName().equalsIgnoreCase("*NONE"))
                curGroupsHashSet.add(curUser.getGroupProfileName());

            if (curUser.getSupplementalGroupsNumber() > 0)
                curGroupsHashSet.addAll(Arrays.asList(curUser.getSupplementalGroups()));
           
            if (!curGroupsHashSet.isEmpty())
                for (String groupName : allGroupsHashSet) {
                    newRow.addElement((curGroupsHashSet.contains(groupName) ? "X" : ""));
                }
            else
                for (int i=0; i<allGroupsHashSet.size(); i++)
                    newRow.addElement("");
            
            //rows.addElement(newRow);
            dbTempConnection.insertrow(authMatrixName, newRow);
        }

        return authMatrixName;
    }

    public Enumeration getObjectPrivileges(String objectPath) 
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        Permission objectPermission;
        Enumeration detailedObjectPermissions;
        
        try {
            objectPermission = new Permission(secure ? secureConnection : insecureConnection, objectPath);
            detailedObjectPermissions = objectPermission.getUserPermissions();
        } catch (AS400Exception ex) {
            return null;
        }
        
        return detailedObjectPermissions;
    }     

    public String printQSYSPrivileges(String objName, String objLibrary, String objType)
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        QSYSObjectPathName objPath = new QSYSObjectPathName(objLibrary, objName, objType);
        
        return printQSYSPrivileges(objPath.getPath());
    }
    
    public String printQSYSPrivileges(String objectPath)
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        Permission objectPermission;
        Enumeration detailedObjectPermissions;
        
        objectPermission = new Permission(secure ? secureConnection : insecureConnection, objectPath);
                
        String outputString = "";  
                
        QSYSObjectPathName pathName = new QSYSObjectPathName(objectPath);
        outputString += "Object . . . . . . . . : " + pathName.getObjectName() + "\n";
        outputString += "  Library. . . . . . . : " + pathName.getLibraryName() + "\n";
        outputString += "Object type. . . . . . : " + pathName.getObjectType() + "\n";
        outputString += "Primary group  . . . . : " + objectPermission.getPrimaryGroup() + "\n";
        outputString += "ASP device . . . . . . : " + pathName.getAspName() + "\n\n";      
        outputString += "Owner  . . . . . . . . : " + objectPermission.getOwner() + "\n";
        outputString += "Authorization list . . : " + objectPermission.getAuthorizationList() + "\n\n";
        outputString += "                      Object    -----Object------   ------Data-------\n";
        outputString += "User       Group      Authority O   M   E   A   R   R   A   U   D   E\n";
        
        try {            
            detailedObjectPermissions = objectPermission.getUserPermissions();
        } catch (Exception ex) {
            outputString += "\n\nNot authorized to view the detailed access rights.";
            return outputString; 
        }
        
        while (detailedObjectPermissions.hasMoreElements()) {
            QSYSPermission detailedQSYSperm = (QSYSPermission)detailedObjectPermissions.nextElement();
            switch (detailedQSYSperm.getGroupIndicator()) {
                case QSYSPermission.GROUPINDICATOR_SPECIALVALUE:
                case QSYSPermission.GROUPINDICATOR_USER: 
                    outputString += padTextRight(detailedQSYSperm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case QSYSPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + padTextRight(detailedQSYSperm.getUserID(), 10) + " ";                                                                                        
                    break;                                                    
            }
            
            outputString += padTextRight(detailedQSYSperm.getObjectAuthority(), 9) + " ";
            outputString += (detailedQSYSperm.isOperational() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isManagement()? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isExistence()? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isAlter() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isReference() ? "X" : " ") + "   ";
            outputString += (detailedQSYSperm.isRead() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isAdd() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isUpdate() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isDelete() ? "X" : " ") + "  ";
            outputString += (detailedQSYSperm.isExecute() ? "X" : " ") + "\n";                                            
        }                                      
        return outputString;
    }
 
    public String printDLOPrivileges(String objectPath)
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        Permission objectPermission;
        Enumeration detailedObjectPermissions;
        
        objectPermission = new Permission(secure ? secureConnection : insecureConnection, objectPath);
                
        String outputString = "";  
                
        outputString += "Object . . . . . . . . : " + objectPath + "\n";
        outputString += "Owner  . . . . . . . . : " + objectPermission.getOwner() + "\n";
        outputString += "Primary group  . . . . : " + objectPermission.getPrimaryGroup() + "\n";
        outputString += "Authorization list . . : " + objectPermission.getAuthorizationList() + "\n\n";
        outputString += "                      Data     \n";
        outputString += "User       Group      Authority\n";
        
        try {            
            detailedObjectPermissions = objectPermission.getUserPermissions();
        } catch (Exception ex) {
            outputString += "\n\nNot authorized to view the detailed access rights.";
            return outputString; 
        }
        
        while (detailedObjectPermissions.hasMoreElements()) {
            DLOPermission detailedDLOperm =(DLOPermission)detailedObjectPermissions.nextElement();
            switch (detailedDLOperm.getGroupIndicator()) {
                case DLOPermission.GROUPINDICATOR_SPECIALVALUE:
                case DLOPermission.GROUPINDICATOR_USER: 
                    outputString += padTextRight(detailedDLOperm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case DLOPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + padTextRight(detailedDLOperm.getUserID(), 10) + " ";                                                                                        
                    break;                                                    
            }
            outputString += detailedDLOperm.getDataAuthority() + "\n";
        }                                          
                                              
        return outputString;
    }

    public String printRootPrivileges(String objectPath)
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        Permission objectPermission;
        Enumeration detailedObjectPermissions;
        
        objectPermission = new Permission(secure ? secureConnection : insecureConnection, objectPath);
        
        String outputString = "";  
                
        outputString += "Object . . . . . . . . : " + objectPath + "\n";
        outputString += "Owner  . . . . . . . . : " + objectPermission.getOwner() + "\n";
        outputString += "Primary group  . . . . : " + objectPermission.getPrimaryGroup() + "\n";
        outputString += "Authorization list . . : " + objectPermission.getAuthorizationList() + "\n\n";
        outputString += "                      Data      --Object--\n";
        outputString += "User       Group      Authority M  E  A  R\n";        

        try {            
            detailedObjectPermissions = objectPermission.getUserPermissions();
        } catch (Exception ex) {
            outputString += "\n\nNot authorized to view the detailed access rights.";
            return outputString; 
        }        
        
        while (detailedObjectPermissions.hasMoreElements()) {
            RootPermission detailedRootPerm =(RootPermission)detailedObjectPermissions.nextElement();
            switch (detailedRootPerm.getGroupIndicator()) {
                case RootPermission.GROUPINDICATOR_SPECIALVALUE:
                case RootPermission.GROUPINDICATOR_USER: 
                    outputString += padTextRight(detailedRootPerm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case RootPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + padTextRight(detailedRootPerm.getUserID(), 10) + " ";                                                                                        
                    break;                                                    
            }
            
            outputString += padTextRight(detailedRootPerm.getDataAuthority(), 9) + " ";
            outputString += (detailedRootPerm.isManagement()? "X" : " ") + "  ";
            outputString += (detailedRootPerm.isExistence()? "X" : " ") + "  ";
            outputString += (detailedRootPerm.isAlter() ? "X" : " ") + "  ";
            outputString += (detailedRootPerm.isReference() ? "X" : " ") + "\n";
        }                                    
        return outputString;
    }    
            
    public String printObjectPrivileges(String objectPath)
            throws AS400Exception, AS400SecurityException, ConnectionDroppedException, 
            ErrorCompletingRequestException, InterruptedException, IOException, 
            ObjectDoesNotExistException {

        if (insecureConnection==null && secureConnection==null)
            return null;
        
        Permission objectPermission;
        String outputString = "";
        
        IFSJavaFile ifsJavaFile = new IFSJavaFile(secure ? secureConnection : insecureConnection, objectPath);
        outputString = "Basic access rights (Read, Write, eXecute): \n";
        outputString += (ifsJavaFile.canRead() ? "R" : "");
        outputString += (ifsJavaFile.canWrite() ? "W" : "");
        outputString += (ifsJavaFile.canExecute() ? "X" : "") + "\n\n";
                
        try {
            objectPermission = new Permission(secure ? secureConnection : insecureConnection, objectPath);
        } catch (AS400Exception ex) {
            outputString += "Not authorized to obtain the access rights information.";
            return outputString;
        }

        
        
        outputString += "Object type: . . . . . : " + (objectPermission.getType() == Permission.TYPE_QSYS ?
                                                       "QSYS object" : 
                                                     (objectPermission.getType() == Permission.TYPE_DLO ?
                                                       "QDLS file" : "IFS file")) + "\n";

        switch (objectPermission.getType()) {
            case Permission.TYPE_QSYS: outputString += printQSYSPrivileges(objectPath);
                                      break;
            
            case Permission.TYPE_DLO: outputString += printDLOPrivileges(objectPath);
                                      break;
            
            case Permission.TYPE_ROOT: outputString += printRootPrivileges(objectPath);                                      
                                      break;
        }

        return outputString;
    }    

    public boolean createUserSpace2(String uspcName, String uspcLibrary, String extAttr, int initialSize, String description)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {

        if (insecureConnection==null && secureConnection==null)
            return false;
        
        UserSpace userSpace = new UserSpace((secure ? secureConnection : insecureConnection), 
                                            "/QSYS.LIB/" + uspcLibrary.toUpperCase() + ".LIB/"
                                            + uspcName.toUpperCase() + ".USRSPC");
        
        userSpace.create(initialSize, true, extAttr, (byte)0x00, description, "*EXCLUDE");
        
        return true;
    }
    
    public boolean createUserSpace(String uspcName, String uspcLibrary, String extAttr, int initialSize, String description)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        /* 
         * http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_61/apis/quscrtus.htm
         * 
         Required Parameter Group:

            1	Qualified user space name	Input	Char(20) <- uspcName/uspcLibrary
            2	Extended attribute	Input	Char(10) <- extAttr
            3	Initial size	Input	Binary(4) <-initialSize
            4	Initial value	Input	Char(1) <- here hard-coded 0x00
            5	Public authority	Input	Char(10) <- here hard-coded *EXCLUDE 
            6	Text description	Input	Char(50) <- description

              Optional Parameter Group 1:

            7	Replace	Input	Char(10)
            8	Error code	I/O	Char(*)

              Optional Parameter Group 2:

            9	Domain	Input	Char(10)

              Optional Parameter Group 3:

            10	Transfer size request	Input	Binary(4)
            11	Optimum space alignment	Input	Char(1)

              Default Public Authority: *USE

              Threadsafe: Yes


         */
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        ProgramCall quscrtus=  new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] quscrtusParms = new ProgramParameter[6]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char1Converter = new AS400Text(1);
        AS400Text char10Converter = new AS400Text(10);
        AS400Text char20Converter = new AS400Text(20);        
        AS400Text char50Converter = new AS400Text(50);
        
        
        String userSpaceName = (uspcName.length() > 10 ? uspcName.substring(0,10).toUpperCase() : 
                                                         uspcName.toUpperCase());
        while (userSpaceName.length() < 10)
            userSpaceName += " ";        
                
        String userSpaceLib = (uspcLibrary.length() > 10 ? uspcLibrary.substring(0,10).toUpperCase() : 
                                                           uspcLibrary.toUpperCase());
        while (userSpaceLib.length() < 10)
            userSpaceLib += " ";        
        
        String extendedAttribute = (extAttr.length() > 10 ? extAttr.substring(0,10).toUpperCase() :
                                                            extAttr.toUpperCase());
        while (extendedAttribute.length() < 10)
            extendedAttribute += " ";        
        
        String userSpaceDescription = (description.length() > 50 ? description.substring(0,50) : 
                                                            description);
        while (userSpaceDescription.length() < 10)
            userSpaceDescription += " ";        
        
        quscrtusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        quscrtusParms[1] = new ProgramParameter(char10Converter.toBytes(extendedAttribute));
        quscrtusParms[2] = new ProgramParameter(bin4.toBytes(new Integer(initialSize)));
        quscrtusParms[3] = new ProgramParameter(char1Converter.toBytes(new String(new byte[] {0x00})));
        quscrtusParms[4] = new ProgramParameter(char10Converter.toBytes("*EXCLUDE  "));
        quscrtusParms[5] = new ProgramParameter(char50Converter.toBytes(userSpaceDescription));
        
        quscrtus.setProgram("/qsys.lib/quscrtus.pgm", quscrtusParms);
                
        return quscrtus.run();        
    }
        
    public boolean makeUserSpaceAutoExtendible(String uspcName, String uspcLibrary, boolean autoExtendible)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {

        if (insecureConnection==null && secureConnection==null)
            return false;
        
        ProgramCall quscusat =  new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] quscusatParms = new ProgramParameter[4]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char1Converter = new AS400Text(1);
        AS400Text char10Converter = new AS400Text(10);
        AS400Text char20Converter = new AS400Text(20);        
        AS400Text char50Converter = new AS400Text(50);
        
        
        String userSpaceName = _padTrimString(uspcName.toUpperCase(), 10);
                
        String userSpaceLib = _padTrimString(uspcLibrary.toUpperCase(), 10);
                
        AS400DataType[] paramDataType = new AS400DataType[]{
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Text(1)
        };
        
        AS400Structure paramStructure = new AS400Structure(paramDataType);
        AS400Array paramArray = new AS400Array(paramStructure, 1);

        Object paramData[] = new Object[1];
        
        paramData[0] = new Object[]{
            1,//bin4.toBytes(1), //Number of records
            3,//bin4.toBytes(3), //Key
            1,//bin4.toBytes(1), //Length of data
            //(autoExtendible ? char1Converter.toBytes("1") : char1Converter.toBytes("0")) //data
            (autoExtendible ? "1" : "0") //data
        };

        byte[] paramBytes = new byte[13];
        paramBytes = paramArray.toBytes(paramData);
        
        quscusatParms[0] = new ProgramParameter(10);
        quscusatParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        quscusatParms[1] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        quscusatParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        quscusatParms[2] = new ProgramParameter(paramBytes);
        quscusatParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        byte[] errorBytes = new byte[32];
        quscusatParms[3] = new ProgramParameter(errorBytes, 32);
        quscusatParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        
        quscusat.setProgram("/qsys.lib/quscusat.pgm", quscusatParms);
                
        if (!quscusat.run()){
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(quscusat.getMessageList()));
            return false;
        }
        return true;
    }

    public int getUserSpaceLength(String uspcName, String uspcLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {

        if (insecureConnection==null && secureConnection==null)
            return -1;
        
        ProgramCall qusrusat =  new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qusrusatParms = new ProgramParameter[5]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char1Converter = new AS400Text(1);
        AS400Text char10Converter = new AS400Text(10);
        AS400Text char20Converter = new AS400Text(20);        
        AS400Text char8Converter = new AS400Text(8);
        
        
        String userSpaceName = _padTrimString(uspcName.toUpperCase(), 10);
                
        String userSpaceLib = _padTrimString(uspcLibrary.toUpperCase(), 10);
                
        
        qusrusatParms[0] = new ProgramParameter(24);
        qusrusatParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrusatParms[1] = new ProgramParameter(bin4.toBytes(24));
        qusrusatParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrusatParms[2] = new ProgramParameter(char8Converter.toBytes("SPCA0100"));
        qusrusatParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrusatParms[3] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        qusrusatParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);        
        byte[] errorBytes = new byte[32];
        qusrusatParms[4] = new ProgramParameter(errorBytes, 32);
        qusrusatParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        
        qusrusat.setProgram("/qsys.lib/qusrusat.pgm", qusrusatParms);
                
        if (!qusrusat.run()) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qusrusat.getMessageList()));
            return -1;
        }
        
        AS400DataType[] returnArrayType = new AS400DataType[6]; //SPCA0100 format
        returnArrayType[0] = new AS400Bin4();
        returnArrayType[1] = new AS400Bin4();
        returnArrayType[2] = new AS400Bin4();
        returnArrayType[3] = new AS400Text(1);
        returnArrayType[4] = new AS400Text(1);
        returnArrayType[5] = new AS400Text(1);
      
        AS400Structure returnedDataConverter = new AS400Structure(returnArrayType);
        Object[] returnedArray = (Object[]) returnedDataConverter.toObject(qusrusatParms[0].getOutputData(), 0);
        return (Integer)(returnedArray[2]);
    }

    
    public boolean deleteUserSpace(String uspcName, String uspcLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        /* 
         * http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_61/apis/qusdltus.htm
         * 
            Required Parameter Group:

            1	Qualified user space name	Input	Char(20)
            2	Error code	I/O	Char(*)

              Default Public Authority: *USE

              Threadsafe: Yes
         */
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        ProgramCall qusdltus = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qusdltusParms = new ProgramParameter[2]; //only mandatory params at the moment

        AS400Text char20Converter = new AS400Text(20);        
                
        String userSpaceName = (uspcName.length() > 10 ? uspcName.substring(0,10).toUpperCase() : 
                                                         uspcName.toUpperCase());
        while (userSpaceName.length() < 10)
            userSpaceName += " ";        
                
        String userSpaceLib = (uspcLibrary.length() > 10 ? uspcLibrary.substring(0,10).toUpperCase() : 
                                                           uspcLibrary.toUpperCase());
        while (userSpaceLib.length() < 10)
            userSpaceLib += " ";        
        
        
        qusdltusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        qusdltusParms[1] = new ProgramParameter(2000);
        
        qusdltus.setProgram("/qsys.lib/qusdltus.pgm", qusdltusParms);
                
        return qusdltus.run();        
    }    
    
    public boolean changeUserSpace(String uspcName, String uspcLibrary, int startingPos, byte[] uspcData)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        /* 
         * http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_61/apis/quschgus.htm?lang=en
         * 

           Required Parameter Group:

            1	Qualified user space name	Input	Char(20) <- uspcName + uspcLibrary
            2	Starting position	Input	Binary(4) <- startingPos
            3	Length of data	Input	Binary(4) <- uspcData.length
            4	Input data	Input	Char(*) <- uspcData
            5	Force changes to auxiliary storage	Input	Char(1) <- hard-coded to 0 (system to decide when to write)

              Optional Parameter:

            6	Error code	I/O	Char(*)

              Default Public Authority: *USE

              Threadsafe: Yes

         */
        if (insecureConnection==null && secureConnection==null)
            return false;
        
        ProgramCall quschgus = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] quschgusParms = new ProgramParameter[5]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char1Converter = new AS400Text(1);
        AS400Text char20Converter = new AS400Text(20);        
                
        String userSpaceName = (uspcName.length() > 10 ? uspcName.substring(0,10).toUpperCase() : 
                                                         uspcName.toUpperCase());
        while (userSpaceName.length() < 10)
            userSpaceName += " ";        
                
        String userSpaceLib = (uspcLibrary.length() > 10 ? uspcLibrary.substring(0,10).toUpperCase() : 
                                                           uspcLibrary.toUpperCase());
        while (userSpaceLib.length() < 10)
            userSpaceLib += " ";        
                
        quschgusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        quschgusParms[1] = new ProgramParameter(bin4.toBytes(new Integer(startingPos)));
        quschgusParms[2] = new ProgramParameter(bin4.toBytes(new Integer(uspcData.length)));
        quschgusParms[3] = new ProgramParameter(uspcData);
        quschgusParms[4] = new ProgramParameter(char1Converter.toBytes("0"));        
        quschgus.setProgram("/qsys.lib/quschgus.pgm", quschgusParms);
        
                
        return quschgus.run();        
    }

    public String retrieveUserSpace(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        return retrieveUserSpace(uspcName, uspcLibrary, fieldFormat, 0);
        
    }
    
    public Object[] getUserSpaceHeaderData(String uspcName, String uspcLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        ProgramCall qusrtvus = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qusrtvusParms = new ProgramParameter[4]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char20Converter = new AS400Text(20);        

        String userSpaceName = _padTrimString(uspcName.toUpperCase(), 10);

        String userSpaceLib = _padTrimString(uspcLibrary.toUpperCase(), 10);


        qusrtvusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
        qusrtvusParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrtvusParms[1] = new ProgramParameter(bin4.toBytes(125));           
        qusrtvusParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrtvusParms[2] = new ProgramParameter(bin4.toBytes(16));           
        qusrtvusParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrtvusParms[3] = new ProgramParameter(16);           
        qusrtvusParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qusrtvus.setProgram("/qsys.lib/qusrtvus.pgm", qusrtvusParms);
        if (!qusrtvus.run()) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qusrtvus.getMessageList()));
            return null;
            }

        //https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/apiref/usfexample.htm
        //Offset +7C
        AS400DataType[] headerFormat = new AS400DataType[]{
            new AS400Bin4(), //Offset to list data section
            new AS400Bin4(), //List data section size
            new AS400Bin4(), //Number of list entries
            new AS400Bin4() //Size of each entry
        };
        
        AS400Structure returnedDataConverter = new AS400Structure(headerFormat);
        return (Object[]) returnedDataConverter.toObject(qusrtvusParms[3].getOutputData(), 0);            
    }
    
    public String retrieveUserSpace(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat, int skipHeaderBytes)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {

        /*
        Note:
            fieldFormat defines how many fields are included (fieldFormat.length) and what is their length (every byte).
            Since the data is converted to String and put into a database, it is up to the external function to 
            interpret the data from the database.
        */
        String dbUserSpaceName = "";        
        
        int userSpaceLength = getUserSpaceLength(uspcName, uspcLibrary);
        int fieldLength = _sumDataTypeFields(fieldFormat);
        
        if ((insecureConnection==null && secureConnection==null) || 
             fieldLength == 0 || userSpaceLength <=0 || userSpaceLength < fieldLength )
            return dbUserSpaceName;

        dbUserSpaceName = dbTempConnection.createTempTable(uspcName+uspcLibrary, fieldFormat.length);
        
        Object[] offsetData = getUserSpaceHeaderData(uspcName, uspcLibrary);
        int dataOffset = (Integer)offsetData[0];
        int maxRecords = (userSpaceLength - dataOffset) / fieldLength;
        for (int curRecord=0; curRecord<maxRecords; curRecord++) {
            ProgramCall qusrtvus = new ProgramCall(secure ? secureConnection : insecureConnection);        
            ProgramParameter[] qusrtvusParms = new ProgramParameter[4]; //only mandatory params at the moment

            AS400Bin4 bin4 = new AS400Bin4();      
            AS400Text char20Converter = new AS400Text(20);        

            String userSpaceName = _padTrimString(uspcName.toUpperCase(), 10);

            String userSpaceLib = _padTrimString(uspcLibrary.toUpperCase(), 10);


            qusrtvusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
            qusrtvusParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvusParms[1] = new ProgramParameter(bin4.toBytes((curRecord*fieldLength)+1+dataOffset));           
            qusrtvusParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvusParms[2] = new ProgramParameter(bin4.toBytes(fieldLength));           
            qusrtvusParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvusParms[3] = new ProgramParameter(fieldLength);           
            qusrtvusParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvus.setProgram("/qsys.lib/qusrtvus.pgm", qusrtvusParms);
            if (!qusrtvus.run()) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, _stringFromAS400Message(qusrtvus.getMessageList()));
                return "";
            }
            
            AS400Structure returnedDataConverter = new AS400Structure(fieldFormat);
            Object[] returnedArray = (Object[]) returnedDataConverter.toObject(qusrtvusParms[3].getOutputData(), 0);
            if (returnedArray.length != fieldFormat.length) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Received data format does not match.");
                return "";
            }
            
            Vector arrayData = new Vector();
            
            for (Object arrayElement : returnedArray)
                arrayData.addElement(arrayElement);
            
            dbTempConnection.insertrow(dbUserSpaceName, arrayData);
        }
        
        return dbUserSpaceName;
    }
    
    
    public String getPTFs2() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{

        String dbPTFName = "";
        try {
            while (isActiveTask)
                Thread.sleep(1);
            
            createUserSpace("ALLPTFS", curLib, "ALLPTFS", 64000, "PTF user space");
            if (!makeUserSpaceAutoExtendible("ALLPTFS", curLib, true))
                return dbPTFName;

            String userSpaceName = _padTrimString("ALLPTFS   " + curLib.toUpperCase(), 20);
            
            ProductList productList = new ProductList(secure ? secureConnection : insecureConnection);
            Product[] products = productList.getProducts();

            isActiveTask = true;
            currentTaskProgress = 0;
            
            int maxObjects = products.length;
            int objectCounter = 0;
            for (Product product : products) {
                //product.
                
                if (!(product.isInstalled() || product.isSupported() || product.isLoadInError()))
                {
                    currentTaskProgress = (int)(100.0f * objectCounter/maxObjects);
                    objectCounter++;
                    continue;
                }                        
                
                if (isCancelledTask){
                    isCancelledTask = false;
                    isActiveTask = false;
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Task cancelled");
                    return null;
                }
                String productDescription = _padTrimString(product.getProductID(), 7) +
                                            _padTrimString("*ALL", 6) +
                                            _padTrimString("*ALL", 4) +
                                            _padTrimString("*ALL", 10) +
                                            "0" + "0" + new String(new byte[] {0x00,0x00,0x00,0x00,0x00,
                                                                               0x00,0x00,0x00,0x00,0x00,
                                                                               0x00,0x00,0x00,0x00,0x00,
                                                                               0x00,0x00,0x00,0x00,0x00,0x00});
                
                        ProgramParameter[] qpzlstfxParms = new ProgramParameter[4];

                        AS400Text char8Converter = new AS400Text(8);
                        AS400Text char20Converter = new AS400Text(20);        
                        AS400Text char50Converter = new AS400Text(50);       
                        AS400Bin4 bin4 = new AS400Bin4();                                                                        
                                                
                        qpzlstfxParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
                        qpzlstfxParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
                        qpzlstfxParms[1] = new ProgramParameter(char50Converter.toBytes(productDescription));
                        qpzlstfxParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
                        qpzlstfxParms[2] = new ProgramParameter(char8Converter.toBytes("PTFL0100"));
                        qpzlstfxParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
                        byte[] errorBytes = new byte[32];
                        qpzlstfxParms[3] = new ProgramParameter(errorBytes, 32);
                        qpzlstfxParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

                        ServiceProgramCall qpzlstfx = new ServiceProgramCall(secure ? secureConnection : insecureConnection,
                                                                            "/qsys.lib/qpzlstfx.srvpgm", "QpzListPTF",
                                                                            ServiceProgramCall.NO_RETURN_VALUE, qpzlstfxParms);                                
                        if (!qpzlstfx.run()) {                            
                            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, _stringFromAS400Message(qpzlstfx.getMessageList()));
                        }
                        currentTaskProgress = (int)(100.0f * objectCounter/maxObjects);
                        objectCounter++;                        
            }                                                
        } catch (Exception ex) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
        }

        isActiveTask = false;
    
        /*

            Input Parameter Section

            Offset	Type	Field
            Dec	Hex
            0	0	CHAR(10)	User space name specified
            10	A	CHAR(10)	User space library name specified
            20	14	CHAR(50)	Product information
            70	46	CHAR(8)	Format name


            Header Section

            Offset	Type	Field
            Dec	Hex
            0	0	CHAR(10)	User space name used
            10	A	CHAR(10)	User space library name used
            20	14	CHAR(1)	Current IPL source
            21	15	CHAR(1)	Current server IPL source
            22	16	CHAR(1)	Server firmware status


            PTFL0100 Format List Section

            Offset	Type	Field
            Dec	Hex
            0	0	CHAR(7)	PTF ID
            7	7	CHAR(6)	Release level of the PTF
            13	D	CHAR(4)	Product option of the PTF
            17	11	CHAR(4)	Product load of the PTF
            21	15	CHAR(1)	Loaded status
            22	16	CHAR(1)	Save file status
            23	17	CHAR(1)	Cover letter status
            24	18	CHAR(1)	On-order status
            25	19	CHAR(1)	IPL action
            26	1A	CHAR(1)	Action pending
            27	1B	CHAR(1)	Action required
            28	1C	CHAR(1)	IPL required
            29	1D	CHAR(1)	PTF is released
            30	1E	CHAR(2)	Minimum level
            32	20	CHAR(2)	Maximum level
            34	22	CHAR(13)	Status date and time
            47	2F	CHAR(7)	Superseded by PTF ID
            54	36	CHAR(1)	Server IPL required
            55	37	CHAR(13) Creation date and time
            68	44	CHAR(1)	Technology refresh PTF --> V7R1 onwards
                    

        */
        
        AS400DataType[] ptfDataTypeV6R1 = new AS400DataType[]{
            new AS400Text(7),
            new AS400Text(6),
            new AS400Text(4),
            new AS400Text(4),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(2),
            new AS400Text(2),
            new AS400Text(13),
            new AS400Text(7),
            new AS400Text(1),            
            new AS400Text(13)
        };  
        
        AS400DataType[] ptfDataTypeV7R1 = new AS400DataType[]{
            new AS400Text(7),
            new AS400Text(6),
            new AS400Text(4),
            new AS400Text(4),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(1),
            new AS400Text(2),
            new AS400Text(2),
            new AS400Text(13),
            new AS400Text(7),
            new AS400Text(1),            
            new AS400Text(13),
            new AS400Text(1)
        };

        if ((secure ? secureConnection : insecureConnection).getVersion() == 7)
           return retrieveUserSpace("ALLPTFS", curLib, ptfDataTypeV7R1, 101);
        else if ((secure ? secureConnection : insecureConnection).getVersion() == 6)
           return retrieveUserSpace("ALLPTFS", curLib, ptfDataTypeV6R1, 101);
        else return "";
    }
                      
    public TreeModel getIFSTreeModel(){
        return (TreeModel)ifsTreeModel;
    }
    
    public ListModel getIFSListModel(String root){
        ifsListModel = new IFSFileListModel(root);
        return (ListModel)ifsListModel;
    }
    
    public ListModel getIFSListModel(String root, String filter) {
        ifsListModel = new IFSFileListModel(root, filter);
        return (ListModel)ifsListModel;
    }
            
    
    public DefaultTreeCellRenderer getIFSFileTreeRenderer(){
        return (DefaultTreeCellRenderer)ifsFileTreeRenderer;
    }
    
    public boolean restoreLibraryFromSAVF(String savfName, String savfLibrary, String restoreLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
    
        if (insecureConnection==null && secureConnection==null)
            return false;
        
    //http://www-01.ibm.com/support/knowledgecenter/ssw_ibm_i_61/apis/qsrrsto.htm
        /*
                User Space format:
        
                BINARY(4)	Number of variable length records
                Note: These fields repeat for each variable length record.
 	 	BINARY(4)	Length of variable length record
 	 	BINARY(4)	Key
 	 	BINARY(4)	Length of data
 	 	CHAR(*)	Data
        
        Required keys:
        2	CHAR(*)     Saved library	SAVLIB
        3	CHAR(*)     Device	DEV
        4	CHAR(20)    Save file	SAVF
        
            Format Saved library key (2):
                BINARY(4)	Number in array <-- hardcoded "1" (one library to restore)
 	 	CHAR(10)	Library name <-- hardcoded "*ANY"
        
            Format Device key (3):
                BINARY(4)	Number in array <-- hardcoded "1" (one device to use)
 	 	CHAR(10)	Device name <-- hardcoded "*SAVF"

            Format Save file (4):
                CHAR(10)        SAVF Name
                CHAR(10)         SAVF Library

        
        *
        */

        if (createUserSpace("RSTFUSRSPC", "QTEMP", " ", 88, "") == false) {
            return false;
        }

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char10Converter = new AS400Text(10);
        AS400Text char20Converter = new AS400Text(20);        
        
        /*      TITLE                                   LEN     VAL
                Number of variable length records	4	3
                Length of variable length record	4	26
                Key                                     4	2
                Length of data                          4	14
                Data                                    4	1
                                                        10	restoreLibrary
                Length of variable length record	4	26
                Key                                     4	3
                Length of data                          4	14
                Data                                    4	1
                                                        10	"*SAVF"
                Length of variable length record	4	32
                Key                                     4	4
                Length of data                          4	20
                Data                                    10	savfName
                                                        10	savfLibrary
                ===========================================================
                                        Total length:   88
        
        */
        ByteArrayOutputStream userSpaceContent = new ByteArrayOutputStream();
        userSpaceContent.write(bin4.toBytes(new Integer(3)));
        userSpaceContent.write(bin4.toBytes(new Integer(26)));
        userSpaceContent.write(bin4.toBytes(new Integer(2)));
        userSpaceContent.write(bin4.toBytes(new Integer(14)));
        userSpaceContent.write(bin4.toBytes(new Integer(1)));
        userSpaceContent.write(char10Converter.toBytes(padTextRight(restoreLibrary, 10)));
        userSpaceContent.write(bin4.toBytes(new Integer(26)));
        userSpaceContent.write(bin4.toBytes(new Integer(3)));
        userSpaceContent.write(bin4.toBytes(new Integer(14)));
        userSpaceContent.write(bin4.toBytes(new Integer(1)));
        userSpaceContent.write(char10Converter.toBytes("*SAVF     "));
        userSpaceContent.write(bin4.toBytes(new Integer(32)));
        userSpaceContent.write(bin4.toBytes(new Integer(4)));
        userSpaceContent.write(bin4.toBytes(new Integer(20)));
        userSpaceContent.write(char10Converter.toBytes(padTextRight(savfName, 10)));
        userSpaceContent.write(char10Converter.toBytes(padTextRight(savfLibrary, 10)));
        
        if (changeUserSpace("RSTFUSRSPC", "QTEMP", 0, userSpaceContent.toByteArray()) == false) {
            deleteUserSpace("RSTFUSRSPC", "QTEMP");            
            return false;
        }
        
        ProgramCall qsrrsto = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qsrrstoParms = new ProgramParameter[2]; //only mandatory params at the moment    
        
        qsrrstoParms[0] = new ProgramParameter(char20Converter.toBytes("QTEMP     RSTFUSRSPC"));
        qsrrstoParms[1] = new ProgramParameter(2000);
        
        qsrrsto.setProgram("/qsys.lib/qsrrsto.pgm", qsrrstoParms);
        
        if (qsrrsto.run() == false) {
            deleteUserSpace("RSTFUSRSPC", "QTEMP");
            return false;
        } else {
            deleteUserSpace("RSTFUSRSPC", "QTEMP");
            return true;            
        }  
     
    }    

    public String selectIFSFile(String path)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
    
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        IFSJavaFile dirIFS = new IFSJavaFile((secure ? secureConnection : insecureConnection), path);
        JFileChooser fileChooser = new JFileChooser(dirIFS, new IFSSystemView(secure ? secureConnection : insecureConnection));
        Frame popUpFrame = new Frame();
        if (fileChooser.showOpenDialog(popUpFrame) == JFileChooser.APPROVE_OPTION) {
           IFSJavaFile chosenFile = (IFSJavaFile)(fileChooser.getSelectedFile());
           return chosenFile.getName();
        }
        else {
            return null;
        }
    }    
  
    public String selectIFSFile()
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
        
        return selectIFSFile("//");
        
    }
    
    public FileSystemView IFSFileBrowser()
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
    
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        return new IFSSystemView(secure ? secureConnection : insecureConnection);        
    }       
    
    public void restoreSAVF(String savfName)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException {
    
        if (insecureConnection==null && secureConnection==null)
            return;
        
        AS400FileNameConverter savfFile = new AS400FileNameConverter((secure ? secureConnection : insecureConnection), savfName);
        SaveFile savf = new SaveFile((secure ? secureConnection : insecureConnection), 
                                    savfFile.getLibraryName(), savfFile.getFileName());
        
        SaveFileEntry[] savfEntries = new SaveFileEntry[(int)savf.getCurrentNumberOfRecords()];
        savfEntries = savf.listEntries();
        
        Hashtable<String, Integer> savfObjects = new Hashtable<String, Integer>();   
        
        for (int i=0; i<savfEntries.length; i++) {
            if (savfObjects.containsKey(savfEntries[i].getLibrary())){
                savfObjects.put(savfEntries[i].getLibrary(), savfObjects.get(savfEntries[i].getLibrary()) + 1);
            } else {
                savfObjects.put(savfEntries[i].getLibrary(), 1);
            }
            
        }
        
        for (String savfLib: savfObjects.keySet()) {
            restoreLibraryFromSAVF(savfFile.getFileName(), savfFile.getLibraryName(), savfLib);
        }        
    }    
    
    /////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////
    // PRIVATE METHODS
    /////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////

    private void prepareFile(String fileName) throws IOException {
        File workFile = new File(fileName);
        if (!workFile.exists()) {
            workFile.getParentFile().mkdirs();
            workFile.createNewFile();
        }        
    }
    
    private String _convertLongTimeToString(long time){
        Date date = new Date(time);
        Format format = new SimpleDateFormat("yyyy MM dd HH:mm:ss");
        return format.format(date);
    }

    private String _padTrimString(String inputString, int len){
        String outputString = inputString;
        if (outputString.length() > len)
            return outputString.substring(0, len-1);
        
        while (outputString.length() < len)
            outputString += " ";
        
        return outputString;
    }
            
    private String _stringFromAS400Message(AS400Message[] message){
        String outputString = "";
        if (message.length == 0) return "";
        for (int i=0; i<message.length; i++)
            outputString += message[i].getText() + "\n" + message[i].getHelp() + "\n";
        return outputString;
    }

    private String _stringFromArray(String[] stringArray, String separator) {
        if (stringArray.length == 0) return "";
        String outputString = "";
        for (String stringElement : stringArray){
            outputString += (outputString == "" ? "" : separator) + stringElement;
        }
        return outputString;
    }    
 
    private String _hexStringFromEBCDIC(byte[] inputString){

        if (inputString.length == 0) return "";
        
        char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
        char[] outputChars = new char[2 * inputString.length];
        for (int i = 0; i < inputString.length; ++i)
        {
            outputChars[2 * i] = HEX_CHARS[(inputString[i] & 0xF0) >>> 4];
            outputChars[2 * i + 1] = HEX_CHARS[inputString[i] & 0x0F];
        }
        return new String(outputChars);
    }    

    private int _sumDataTypeFields(AS400DataType[] dataTypeArray) {
        if (dataTypeArray.length == 0)
            return 0;
    
        int dataTypeSum = 0;
        
        for (AS400DataType arrayElement : dataTypeArray)
            dataTypeSum += arrayElement.getByteLength();
        
        return dataTypeSum;
    }

    
    private int _sumBytes(byte[] byteArray) {
        if (byteArray.length == 0)
            return 0;
    
        int byteSum = 0;
        
        for (byte arrayElement : byteArray)
            byteSum += arrayElement;
        
        return byteSum;
    }
    
    private String _getLastPrintJobNumber() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, InterruptedException, 
            IOException, ObjectDoesNotExistException {
        JobList jobList = new JobList((secure ? secureConnection : insecureConnection));
        jobList.addJobSelectionCriteria(JobList.SELECTION_USER_NAME, currentJob.getStringValue(Job.CURRENT_USER));
        jobList.addJobAttributeToSortOn(Job.JOB_DATE, Boolean.FALSE);
        jobList.addJobSelectionCriteria(JobList.SELECTION_JOB_NAME, "QPRTJOB");
        jobList.addJobAttributeToRetrieve(Job.JOB_NUMBER);
        jobList.addJobAttributeToRetrieve(Job.JOB_DATE);
        Enumeration jobListEnum = jobList.getJobs();
        Job curJob = (Job)jobListEnum.nextElement();
        if (curJob == null) return null;
        return curJob.getNumber();
    }
    
    private int _getLastPrintNumber(String spoolName) 
            throws PropertyVetoException, AS400Exception, AS400SecurityException, 
            ConnectionDroppedException, ErrorCompletingRequestException, 
            InterruptedException, IOException, RequestNotSupportedException{
        
            SpooledFileList splfList = new SpooledFileList((secure ? secureConnection : insecureConnection));
            splfList.setUserFilter((secure ? secureConnection : insecureConnection).getUserId());          
            splfList.setQueueFilter("/QSYS.LIB/%ALL%.LIB/%ALL%.OUTQ");
            splfList.setStartTimeFilter("*ALL");
            splfList.setStartDateFilter("*ALL");
            splfList.openSynchronously();

            Enumeration spoolfilesListEnum = splfList.getObjects();
           
            int maxNumber = -1;

            while( spoolfilesListEnum.hasMoreElements() )
            {
                SpooledFile spoolFile = (SpooledFile)spoolfilesListEnum.nextElement();

                if (spoolFile != null)
                {
                    if (spoolFile.getStringAttribute(SpooledFile.ATTR_SPOOLFILE).equals(spoolName) &&
                            spoolFile.getIntegerAttribute(SpooledFile.ATTR_SPLFNUM) > maxNumber)
                        maxNumber = spoolFile.getIntegerAttribute(SpooledFile.ATTR_SPLFNUM);
                }
            }
            splfList.close();
            return maxNumber;
    }
       
    private UserList _getAllUserObjects() 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            InterruptedException, IOException, ObjectDoesNotExistException, 
            RequestNotSupportedException{

        if (insecureConnection==null && secureConnection==null)
            return null;    
        
        return new UserList(secure ? secureConnection : insecureConnection);        
    }
    
    public boolean checkUserSpecialAuthority(String userName, String authority) 
            throws AS400SecurityException, ErrorCompletingRequestException, 
            InterruptedException, IOException, ObjectDoesNotExistException {
        boolean spcAut = false;
        if (userName == null) return false;
        
        User curUser = null;
        
        curUser = new User((secure ? secureConnection : insecureConnection), userName);

        if (!curUser.getGroupProfileName().equalsIgnoreCase("*NONE")){             
            spcAut |= new User((secure ? secureConnection : insecureConnection), curUser.getGroupProfileName()).hasSpecialAuthority(authority);
        }        
        
        if (curUser.getSupplementalGroupsNumber() > 0)
            for (String supGroup : curUser.getSupplementalGroups()) {
                spcAut |= new User((secure ? secureConnection : insecureConnection), supGroup).hasSpecialAuthority(authority);
            }
        
        return spcAut;
    }   
    
    private String padTextRight(String inputText, int length)
    {
        if (inputText.length() > length) {
            return inputText.substring(0, length);
        }
        
        String outputText = inputText;
        while (outputText.length() < length) {
            outputText += " ";
        }
        return outputText;
    }
    
    private String prepareAPILengthString(int parameterLength){
        if (parameterLength < 0) return "0000000000.00000";
        
        String parameterText = String.valueOf(parameterLength);
        String padBuffer = "";
        if (parameterText.length() < 10)
            padBuffer = new String(new char[10-parameterText.length()]).replace('\0', '0'); 
        return padBuffer + parameterText + ".00000";
    }
    
    private String getIFSFileName(String path){        
        if ((path.lastIndexOf("/") == -1) && (path.lastIndexOf("\\") == -1)) return path;
        if (path.lastIndexOf("/") == -1) return path.substring(path.lastIndexOf("\\")+1);
        return path.substring(path.lastIndexOf("/")+1);
    }
    
    public DefaultListModel getTableColumnAsList(DefaultTableModel table, int column){
        
        DefaultListModel outputList = new DefaultListModel();
        
        if (column > table.getColumnCount() || table.getRowCount() < 1) 
            return outputList;
        
        for (int row = 0; row < table.getRowCount(); row++)
            outputList.addElement(table.getValueAt(row+1, column));
        
        return outputList;
    }
    
    private class AS400FileNameConverter extends AS400File {

        AS400FileNameConverter(AS400 system, String name) {
            super(system, name);
        }
        
        @Override
        public Record[] readAll() throws AS400Exception, AS400SecurityException, InterruptedException, IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
          
        
    } 
    
    private class IFSFileListModel implements ListModel {

        protected IFSJavaFile root;
        protected IFSFileFilter IFSDirectoryFilter;
        protected FilenameFilter IFSFileFilter;
        protected IFSJavaFile[] contents;
        protected String[] fileList;
        protected String filterString;
        
        public IFSFileListModel(String root){ 
            this.root = new IFSJavaFile(secure ? secureConnection : insecureConnection, root); 
            fileList = this.root.list();
        }

        public IFSFileListModel(String root, String filter){ 
            this.root = new IFSJavaFile(secure ? secureConnection : insecureConnection, root); 
            IFSFileFilter = (File dir, String name) -> {
                String uppercaseName = name.toUpperCase();
                return uppercaseName.endsWith(filter);
            };            
            
            fileList = this.root.list(IFSFileFilter);
        }
        
        @Override
        public int getSize() {
            return fileList.length;
        }

        @Override
        public Object getElementAt(int index) {
            if (index > fileList.length) return null;
            IFSJavaFile element = new IFSJavaFile(secure ? secureConnection : insecureConnection, this.root.getAbsolutePath().replace("\\", "/") + "/" + fileList[index]);
            String accessRights = (element.isDirectory() ? "d" : "");
            accessRights += (element.canRead() ? "r" : "-");
            accessRights += (element.canWrite() ? "w" : "-");
            accessRights += (element.canExecute() ? "x" : "-");            
            accessRights += (element.isHidden() ? "h" : "");
            return fileList[index].substring(0, fileList[index].indexOf("."));
        }

        @Override
        public void addListDataListener(ListDataListener l) {}

        @Override
        public void removeListDataListener(ListDataListener l) {}
        
    }
    
    private class IFSFileTreeModel implements TreeModel {
        protected IFSJavaFile root;
        protected IFSFileFilter IFSDirectoryFilter;
        
        public IFSFileTreeModel(String root){ 
            this.root = new IFSJavaFile(secure ? secureConnection : insecureConnection, root); 
            IFSDirectoryFilter = (IFSFile ifsf) -> {
                try {
                    return ifsf.isDirectory();
                } catch (IOException ex) {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
                    return false;
                }
            };
        }

        public Object getRoot(){ 
            return root; 
        }
                
        public boolean isLeaf(Object node){
            IFSJavaFile nodeFile = ((IFSJavaFile)node);
            if (nodeFile.isDirectory() && !(nodeFile.canExecute())) return true;           
            return ((IFSJavaFile)node).isFile(); 
        }

        public int getChildCount(Object parent){
            String[] children;
            try {
                children = ((IFSJavaFile)parent).list(IFSDirectoryFilter);
            } catch (Exception ex) {
                return 0;
            }
            if (children == null) return 0;
                return children.length;
        }
  
        public Object getChild(Object parent, int index){
            String[] children = ((IFSJavaFile)parent).list(IFSDirectoryFilter);
            if ((children == null) || (index >= children.length)) return null;
            return new IFSJavaFile((IFSJavaFile) parent, children[index]);
        }

        public int getIndexOfChild(Object parent, Object child){
            String[] children = ((IFSJavaFile)parent).list(IFSDirectoryFilter);
            if (children == null) return -1;
            String childname = ((IFSJavaFile)child).getName();
            for(int i = 0; i < children.length; i++){
                if (childname.equals(children[i])) return i;
            }
            return -1;
        }

        @Override
        public void valueForPathChanged(TreePath path, Object newvalue) {}
        @Override
        public void addTreeModelListener(TreeModelListener l) {}
        @Override
        public void removeTreeModelListener(TreeModelListener l) {}
    }

    public class IFSFileTreeCellRenderer extends DefaultTreeCellRenderer {

        private FileSystemView fsv = FileSystemView.getFileSystemView();

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, 
                boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (value instanceof IFSJavaFile) {
                IFSJavaFile file = (IFSJavaFile) value;
                setText(file.getName());
                if (file.isDirectory() && !file.canExecute()) {
                    setEnabled(false);
                }
            }
            return this;
        }
    }
}
