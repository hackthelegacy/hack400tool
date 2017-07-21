//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2017  Bart Kulach
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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
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
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JTree;
import javax.swing.ListModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.TreeModelListener;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class IBMiConnector {

    public static final int CL_COMMAND_EXEC_PLAIN = 100;
    public static final int CL_COMMAND_EXEC_JDBC = 101;
    public static final int CL_COMMAND_EXEC_QSHELL = 102;
    
    public static final int PASSWORD_TYPE_NOPWD = 100;
    public static final int PASSWORD_TYPE_NOPWDCHK = 101;
    public static final int PASSWORD_TYPE_NOPWDSTS = 102;

    public static final int PASSWORD_HASH_FIRSTDES = 0;
    public static final int PASSWORD_HASH_SECONDDES = 1;
    public static final int PASSWORD_HASH_DES = 7;
    public static final int PASSWORD_HASH_LMHASH = 2;
    public static final int PASSWORD_HASH_HMACSHA1UC = 3;
    public static final int PASSWORD_HASH_HMACSHA1MC = 6;
    public static final int PASSWORD_HASH_UNKNOWNHASH = 4;
    public static final int PASSWORD_HASH_ALLDATA = 5;    
        
    private static int O_CREAT = 00010;
    private static int O_EXCL  = 00020;
    private static int O_TRUNC = 00100;

    private static int O_RDONLY  = 00001;
    private static int O_WRONLY  = 00002;
    private static int O_RDWR    = 00004;

    private static int S_IRWXU = 0000700;
    private static int S_IRUSR = 0000400;
    private static int S_IWUSR = 0000200;
    private static int S_IXUSR = 0000100;

    private static int S_IRWXG = 0000070;
    private static int S_IRGRP = 0000040;
    private static int S_IWGRP = 0000020;
    private static int S_IXGRP = 0000010;
    
    private static int S_IRWXO = 0000007;
    private static int S_IROTH = 0000004;
    private static int S_IWOTH = 0000002;
    private static int S_IXOTH = 0000001;
   
    private AS400 insecureConnection = null;
    private SecureAS400 secureConnection = null;
    private boolean secure = false;

    private IFSFileOutputStream stdinQShell;
    private IFSFileInputStream stdoutQShell;
    private IFSFileInputStream stderrQShell;
    private long fdStdin;
    private long fdStdout;
    private long fdStderr;
    private boolean isQShellOnline = false;
    
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
    
    private static final int MAX_THREADS = 20;
    private static final int SLEEP_TIME = 100; 
    private static final int MAX_SLEEP = 5000; 
    
    private static final String DEFAULT_OUTQ_NAME = "HACKOUTQ";
    private static final String DEFAULT_SPLF_NAME = "HACKSPLF";
    
    private static final int DEFAULT_USERSPACE_READ_BUFFER_SIZE = 2097152;
    
    public IBMiConnector(String serverAddress, boolean useSSL, boolean useJDBC, boolean useGUI, boolean useSockets, boolean useNetSockets, String temporaryLibrary, String userName, String password, boolean useProxy, String proxyServer) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{

                
        //Establish connection to the local temporary database
        dbTempConnection = new SqliteDbConnector(new SimpleDateFormat("YYMMddHHmmSS").format(new Date()), true);           
        
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

        //SSL certificate bypass
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) { }
            public void checkServerTrusted(X509Certificate[] certs, String authType) { }

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] xcs, String string) throws CertificateException {
                return; 
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] xcs, String string) throws CertificateException {
                return; 
            }

        } };

        SSLContext sc = SSLContext.getInstance("SSL");        
        sc.init(null, trustAllCerts, new java.security.SecureRandom());    
        SSLContext.setDefault(sc);
        // End SSL certificate bypass
                
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
        
        curLib = ((temporaryLibrary == null || temporaryLibrary.isEmpty()) ? "QTEMP" : temporaryLibrary.substring(0, (temporaryLibrary.length() < 10 ? temporaryLibrary.length() : 10)).toUpperCase());
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
        
        String stdoutFileName = "/tmp/stdout" + new SimpleDateFormat("YYMMddHHmmSS").format(new Date());
        String stderrFileName = "/tmp/stderr" + new SimpleDateFormat("YYMMddHHmmSS").format(new Date());
        fdStdout = openFileDescriptor(stdoutFileName, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
        fdStderr = openFileDescriptor(stderrFileName, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
        if ((fdStdout>>32) == 1 && (fdStderr>>32) == 2) {
            runCLCommand("ADDENVVAR ENVVAR(QIBM_USE_DESCRIPTOR_STDIO) VALUE('Y')");
            runQShellCommand("chmod 666 " + stdoutFileName + " > /dev/null");
            runQShellCommand("chmod 666 " + stderrFileName + " > /dev/null");
            stdoutQShell = new IFSFileInputStream((secure ? secureConnection : insecureConnection), stdoutFileName);
            stderrQShell = new IFSFileInputStream((secure ? secureConnection : insecureConnection), stderrFileName);        
            isQShellOnline = true;
        } else{
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "QShell connection could not be initialized (cannot open stdout/stderr)."); 
        }
        //DEBUG
        //END DEBUG
        
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Connected.");        
    }

    public IBMiConnector(String serverAddress, boolean useSSL, boolean useJDBC, boolean useGUI, boolean useSockets, boolean useNetSockets, String temporaryLibrary, String userName, String password) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{
        this(serverAddress, useSSL, useJDBC, useGUI, useSockets, useNetSockets, temporaryLibrary, userName, password, false, "");
    }
    
    public IBMiConnector(String serverAddress, boolean useSSL, boolean useJDBC, String temporaryLibrary, String userName, String password)
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{
        this(serverAddress, useSSL, useJDBC, false, false, false, temporaryLibrary, userName, password);
    }
    
    public IBMiConnector(String serverAddress, boolean useSSL, String temporaryLibrary, String userName, String password)
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{
        this(serverAddress, useSSL, true, false, false, false, temporaryLibrary, userName, password);
    }
    
    public IBMiConnector(String serverAddress, boolean useSSL, String temporaryLibrary) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{
        this(serverAddress, useSSL, temporaryLibrary, "", "");
    }

    public IBMiConnector(String serverAddress, String userName, String password) 
            throws AS400SecurityException, IOException, 
            ErrorCompletingRequestException, InterruptedException, 
            PropertyVetoException, ObjectDoesNotExistException, SQLException, KeyManagementException, NoSuchAlgorithmException{
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
        isQShellOnline = false;
        IFSFile stdoutFile = new IFSFile((secure ? secureConnection : insecureConnection), stdoutQShell.getPath());
        stdoutFile.delete();
        IFSFile stderrFile = new IFSFile((secure ? secureConnection : insecureConnection), stderrQShell.getPath());
        stderrFile.delete();        
        (secure ? secureConnection : insecureConnection).disconnectAllServices();
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Disconnected.");
        dbTempConnection.disconnect();
        dbTempConnection.deleteDatabase();
    }
    
    public boolean isQShellOnline(){
        return isQShellOnline;
    }
    
    public int checkQShellStdoutAvailableBytes() throws IOException{
        if (stdoutQShell==null) return -1;
        return stdoutQShell.available();
    }
    
    public int checkQShellStderrAvailableBytes() throws IOException{
        if (stderrQShell==null) return -1;
        return stderrQShell.available();
    }
    
    public String readQShellStdout() throws IOException{
        byte[] buffer = new byte[stdoutQShell.available()];
        stdoutQShell.read(buffer);
        return new AS400Text(buffer.length).toObject(buffer).toString();
    }

    public String readQShellStderr() throws IOException{
        byte[] buffer = new byte[stderrQShell.available()];
        stderrQShell.read(buffer);
        return new AS400Text(buffer.length).toObject(buffer).toString();
    }
    
    private long openFileDescriptor(String path, int oflag, int mode) 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, 
            InterruptedException, ObjectDoesNotExistException{
        ProgramParameter[] qp0llib1Parms = new ProgramParameter[3];
        
        qp0llib1Parms[0] = new ProgramParameter(new AS400Text(path.length()+1).toBytes(path + "\0"));
        qp0llib1Parms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qp0llib1Parms[1] = new ProgramParameter(new AS400Bin4().toBytes(oflag));
        qp0llib1Parms[1].setParameterType(ProgramParameter.PASS_BY_VALUE);
        qp0llib1Parms[2] = new ProgramParameter(new AS400Bin4().toBytes(mode));
        qp0llib1Parms[2].setParameterType(ProgramParameter.PASS_BY_VALUE);        

        ServiceProgramCall qp0llib1 = new ServiceProgramCall((secure ? secureConnection : insecureConnection),
                                        "/qsys.lib/qp0llib1.srvpgm", "open",
                                        ServiceProgramCall.RETURN_INTEGER, qp0llib1Parms);                                
        if (!qp0llib1.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qp0llib1.getMessageList()));
            return -1;
        }       
        //Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.hexStringFromEBCDIC(qp0llib1.getReturnValue()));
        return (long)new AS400Bin8().toObject(qp0llib1.getReturnValue());
    }

    private int closeFileDescriptor(long fildes) throws PropertyVetoException, AS400SecurityException, ErrorCompletingRequestException, IOException, InterruptedException, ObjectDoesNotExistException{
        ProgramParameter[] qp0llib1Parms = new ProgramParameter[1];
        
        qp0llib1Parms[0] = new ProgramParameter(new AS400Bin8().toBytes(fildes));
        qp0llib1Parms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ServiceProgramCall qp0llib1 = new ServiceProgramCall((secure ? secureConnection : insecureConnection),
                                        "/qsys.lib/qp0llib1.srvpgm", "close",
                                        ServiceProgramCall.RETURN_INTEGER, qp0llib1Parms);                                
        if (!qp0llib1.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qp0llib1.getMessageList()));
            return -1;
        }       
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.hexStringFromEBCDIC(qp0llib1.getReturnValue()));
        return qp0llib1.getIntegerReturnValue();
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
            IBMiUtilities.prepareFile(fileName);
            FileOutputStream fileOutStream = new FileOutputStream(fileName);
            fileOutStream.write(binaryInput);
            fileOutStream.close();
        } catch (Exception ex) {
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }
        
    public void exportToXLSX(String fileName, DefaultTableModel tableModel){
        if (tableModel == null || fileName == null){
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Errors occured.");            
            return;
        }
        Workbook excelWorkbook = new XSSFWorkbook();
        System.out.println("Save as file: " + fileName);
        try {
            IBMiUtilities.prepareFile(fileName);
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
        if (tableName == null || fileName == null){
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Errors occured.");            
            return;
        }
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
            IBMiUtilities.prepareFile(fileName);
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
            IOException, InterruptedException, RequestNotSupportedException, 
            ObjectDoesNotExistException, SQLException{
                
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CPYSPLF FILE(" + spoolName + ") TOFILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") JOB(" +
                                getLastPrintJobNumber() + "/" + currentJob.getStringValue(Job.CURRENT_USER) + "/QPRTJOB) SPLNBR(*LAST)"));
        
        String outputString = getPhysicalFileMemberAsText(curLib + "/" + DEFAULT_SPLF_NAME + "");
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("RMVM FILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") MBR(*ALL)"));
        return outputString;
    }

    public void getSpoolFileToDOCX(String fileName, String spoolName) 
            throws PropertyVetoException, AS400Exception, 
            AS400SecurityException, ErrorCompletingRequestException, 
            IOException, InterruptedException, RequestNotSupportedException, 
            ObjectDoesNotExistException, SQLException{
                
        Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, runCLCommand("CPYSPLF FILE(" + spoolName + ") TOFILE(" + curLib + "/" + DEFAULT_SPLF_NAME + ") JOB(" +
                                getLastPrintJobNumber() + "/" + currentJob.getStringValue(Job.CURRENT_USER) + "/QPRTJOB) SPLNBR(*LAST)"));
        
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
        return _runCLCommand(commandString, CL_COMMAND_EXEC_PLAIN);
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

                qp2shellParms[0] = new ProgramParameter(char22Converter.toBytes("/QOpenSys/usr/bin/qsh\0"));
                qp2shellParms[1] = new ProgramParameter(char3Converter.toBytes("-c\0"));
                qp2shellParms[2] = new ProgramParameter(charConverter.toBytes("system \"" + commandToRun + "\"\0"));
                qp2shell.setProgram("/qsys.lib/qp2shell.pgm", qp2shellParms);

                
                if (!qp2shell.run())
                {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "An unexpected error occured.");
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qp2shell.getMessageList()));
                    return null;
                }    
                return IBMiUtilities.stringFromAS400Message(qp2shell.getMessageList());
            case CL_COMMAND_EXEC_PLAIN: //using regular CL command call
            default:
                CommandCall commandRun = new CommandCall(secure ? secureConnection : insecureConnection);
                commandRun.setThreadSafe(false);
                commandRun.run(commandToRun);
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, "Job " + commandString + " was executed. Job number " + commandRun.getServerJob().getNumber().toString());
                return IBMiUtilities.stringFromAS400Message(commandRun.getMessageList());
        }        
    }   

    public void runQShellCommand(String command) 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, 
            InterruptedException, ObjectDoesNotExistException{
    
        ProgramCall qp2shell = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qp2shellParms = new ProgramParameter[3];

        AS400Text char22Converter = new AS400Text(22);
        AS400Text char3Converter = new AS400Text(3);

        qp2shellParms[0] = new ProgramParameter(char22Converter.toBytes("/QOpenSys/usr/bin/qsh\0"));
        qp2shellParms[1] = new ProgramParameter(char3Converter.toBytes("-c\0"));
        qp2shellParms[2] = new ProgramParameter(new AS400Text(command.length() + 1).toBytes(command + "\0"));
        qp2shell.setProgram("/qsys.lib/qp2shell.pgm", qp2shellParms);

        if (!qp2shell.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qp2shell.getMessageList()));
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
            newRow.addElement(IBMiUtilities.convertLongTimeToString(fileProperties[i].lastModified()));
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
        columnNames.addElement("Description");
        
        for (int i=0; i<list.size(); i++){
            Vector newRow = new Vector();
            SystemValue sysVal = (SystemValue)list.elementAt(i);
            newRow.addElement(sysVal.getName());
            try {
                String sysValString;
                switch (sysVal.getType()) {
                    case SystemValueList.TYPE_ARRAY:
                        sysValString = IBMiUtilities.stringFromArray((String[])sysVal.getValue(), " ");
                        break;                   
                    case SystemValueList.TYPE_DECIMAL:                       
                    case SystemValueList.TYPE_INTEGER:
                        sysValString = String.valueOf(sysVal.getValue());
                    case SystemValueList.TYPE_DATE:
                    case SystemValueList.TYPE_STRING:
                        sysValString = sysVal.getValue().toString().trim();
                        break;
                    default:
                        sysValString = "";
                }
                if (sysValString == null) sysValString = "";
                newRow.addElement(sysValString);
            } catch (Exception ex) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
            }
            newRow.addElement(sysVal.getDescription());
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
            case PASSWORD_HASH_DES:
                return composeDESHashFromTokens(hashString.substring(0,16), hashString.substring(16,32));
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

        String userNameAS400 = IBMiUtilities.padTextRight(userName.toUpperCase(), 10);
                
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qsygetph.getMessageList()));
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qsygetph.getMessageList()));
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qsygenpt.getMessageList()));
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qsyrupwd.getMessageList()));
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
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(2,540);            
            case PASSWORD_HASH_UNKNOWNHASH: // Unknown (hash?) data
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(156,540);
            case PASSWORD_HASH_HMACSHA1MC: // HMAC-SHA1 password (mixed case)
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(70,110);
            case PASSWORD_HASH_HMACSHA1UC: // HMAC-SHA1 password (uppercase)
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(110,150);
            case PASSWORD_HASH_LMHASH: // LM hash
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(34,66);
            case PASSWORD_HASH_DES: // Composed DES hash (PW_TOKENa XOR PW_TOKENb):
                return composeDESHashFromTokens(IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(2,18), 
                                                IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(18,34));
            case PASSWORD_HASH_SECONDDES: // Second DES password token (PW_TOKENb)
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(18,34);
            case PASSWORD_HASH_FIRSTDES: // First DES password (PW_TOKENa)
            default: 
                return IBMiUtilities.hexStringFromEBCDIC(char500Converter.toBytes(qsyrupwdInfo[3])).substring(2,18);
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
        
    public void getJohnPasswordsLM(String fileName) throws IOException{
        getJohnPasswords(PASSWORD_HASH_LMHASH, fileName);
    }

    public void getJohnPasswordsDES(String fileName) throws IOException{
        getJohnPasswords(PASSWORD_HASH_DES, fileName);
    }
    
    public void getJohnPasswordsSHAUpperCase(String fileName) throws IOException{
        getJohnPasswords(PASSWORD_HASH_HMACSHA1UC, fileName);
    }
    
    public void getJohnPasswordsSHAMixedCase(String fileName) throws IOException{
        getJohnPasswords(PASSWORD_HASH_HMACSHA1MC, fileName);
    }

    public void getJohnPasswords(int passType, String fileName) throws IOException{
        DefaultTableModel pwdMatrix = null;
        User curUser;
        Enumeration allUsers;
        String curPassword;
        File outFile = new File(fileName);
        IBMiUtilities.prepareFile(fileName);
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter(outFile));
        
        try {
            allUsers  = getAllUsers();
            while (allUsers.hasMoreElements())
            {
                curUser = (User)allUsers.nextElement();
                curPassword = getEncryptedPassword(curUser.getName(), passType);
                switch (passType) {
                    case PASSWORD_HASH_DES:
                        fileWriter.write(curUser.getName() + ":$as400des$" + curUser.getName() + "*" + curPassword + "\n");
                        break;
                    case PASSWORD_HASH_HMACSHA1UC:
                    case PASSWORD_HASH_HMACSHA1MC:
                        fileWriter.write(curUser.getName() + ":$as400ssha1$" + curPassword + "$" + curUser.getName() + "\n");
                        break;
                    case PASSWORD_HASH_LMHASH:
                    default:
                        fileWriter.write(curUser.getName() + ":" + curPassword + "\n");
                        break;
                }
            }           
        } catch (Exception ex) {
            return;
        }

        fileWriter.close();                
    }
    
    public DefaultTableModel getAuthorisationMatrix(){
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
        columnNames.addElement("User encrypted password (DES-1 hash - PW_TOKENa)");
        columnNames.addElement("User encrypted password (DES-1 hash - PW_TOKENb)");
        columnNames.addElement("User encrypted password (DES-1 hash)");
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
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_DES));
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
            newRow.addElement((curUser.getSupplementalGroups().length == 0 ? "" : IBMiUtilities.stringFromArray(curUser.getSupplementalGroups(), " ")));
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
            newRow.addElement(curUser.getUserActionAuditLevel() == null ? "" : IBMiUtilities.stringFromArray(curUser.getUserActionAuditLevel(), " "));
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

    public String getAuthorisationMatrix2() 
            throws SQLException, AS400SecurityException, ErrorCompletingRequestException, 
            InterruptedException, IOException, ObjectDoesNotExistException{
        String authMatrixName = "";
        
        User runningUser = new User(secure ? secureConnection : insecureConnection, currentJob.getStringValue(Job.CURRENT_USER));
        if (!(runningUser.hasSpecialAuthority("*ALLOBJ") && runningUser.hasSpecialAuthority("*SECADM"))){
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Insufficient privileges for this function. You need to have at least *ALLOBJ and *SECADM. Exiting.");            
            return null;
        }

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
        columnNames.addElement("User encrypted password (DES-1 hash - PW_TOKENa)");
        columnNames.addElement("User encrypted password (DES-1 hash - PW_TOKENb)");
        columnNames.addElement("User encrypted password (DES-1 hash)");
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
        
        authMatrixName = dbTempConnection.createTempTable("istmatrix", columnNames.size());
        
        
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
                newRow.addElement(getEncryptedPasswordFromHashString(encryptedPassword, PASSWORD_HASH_DES));
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
            newRow.addElement((curUser.getSupplementalGroups().length == 0 ? "" : IBMiUtilities.stringFromArray(curUser.getSupplementalGroups(), " ")));
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
            newRow.addElement(curUser.getUserActionAuditLevel() == null ? "" : IBMiUtilities.stringFromArray(curUser.getUserActionAuditLevel(), " "));
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
                    outputString += IBMiUtilities.padTextRight(detailedQSYSperm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case QSYSPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + IBMiUtilities.padTextRight(detailedQSYSperm.getUserID(), 10) + " ";                                                                                        
                    break;                                                    
            }
            
            outputString += IBMiUtilities.padTextRight(detailedQSYSperm.getObjectAuthority(), 9) + " ";
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
                    outputString += IBMiUtilities.padTextRight(detailedDLOperm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case DLOPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + IBMiUtilities.padTextRight(detailedDLOperm.getUserID(), 10) + " ";                                                                                        
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
                    outputString += IBMiUtilities.padTextRight(detailedRootPerm.getUserID(), 10) + "            ";                                                                                        
                    break;
                case RootPermission.GROUPINDICATOR_GROUP: 
                    outputString += "*GROUP     " + IBMiUtilities.padTextRight(detailedRootPerm.getUserID(), 10) + " ";                                                                                        
                    break;                                                    
            }
            
            outputString += IBMiUtilities.padTextRight(detailedRootPerm.getDataAuthority(), 9) + " ";
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
        
    private String getIFSDirectoryStructure(final String dbName, String path) throws SQLException {
                              
        IFSJavaFile ifsJavaFile = new IFSJavaFile((secure ? secureConnection : insecureConnection), path);
        
        Vector dirData = new Vector();
        dirData.addElement(path);
        dirData.addElement(String.valueOf(ifsJavaFile.canRead()));
        dirData.addElement(String.valueOf(ifsJavaFile.canWrite()));
        dirData.addElement(String.valueOf(ifsJavaFile.canExecute()));
        dbTempConnection.insertrow(dbName, dirData);
        
        try {
            File[] ifsJavaFiles = ifsJavaFile.listFiles();
            for (final File ifsJavaFileEntry : ifsJavaFiles) {
   /*             if (ifsJavaFileEntry.isDirectory()) {
                    Thread t = new Thread(new Runnable() { public void run() { 
                        try {       
                            getIFSDirectoryStructure(dbName, ifsJavaFileEntry.getAbsolutePath());
                        } catch (SQLException ex) {
                        }
                    }});
                    t.start();
                }*/
            }
        } catch (Exception e) {
        }        
        return null;
    }
    
    public String getIFSDirectoryStructure() throws SQLException {
        
        if (insecureConnection==null && secureConnection==null)
            return null;
        
        String dbName = dbTempConnection.createTempTable("IFSDirStructure", 4);
        /*
            DB structure: Full path, r, w, x
        */        
        return getIFSDirectoryStructure(dbName, "/");
    }
    
    public String getExitPointInfo() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*

        Retrieve Exit Information (QUSRTVEI) API

          Required Parameter Group:

        1 	Continuation handle                     Input 	Char(16)
        2 	Receiver variable                       Output 	Char(*)
        3 	Length of receiver variable             Input 	Binary(4)
        4 	Format name                             Input 	Char(8)
        5 	Exit point name                         Input 	Char(20)
        6 	Exit point format name                  Input 	Char(8)
        7 	Exit program number                     Input 	Binary(4)
        8 	Exit program selection criteria 	Input 	Char(*)
        9 	Error code                              I/O 	Char(*)
        
        */
        
        AS400Text char8Converter = new AS400Text(8);
        AS400Text char16Converter = new AS400Text(16);    
        AS400Text char20Converter = new AS400Text(20);    
        AS400Bin4 bin4 = new AS400Bin4(); 
        
        String[] exitPgmTableColumns = {"ExitPointName", "ExitPointFormatName", "RegisteredExitPoint", 
                                        "CompleteEntry", "ExitProgramNumber", "ExitProgramName", 
                                        "ExitProgramLibraryName", "ExitProgramDescriptionIndicator", 
                                        "ExitProgramDescriptionMessageFileName", 
                                        "ExitProgramDescriptionMessageFileLibraryName", 
                                        "ExitProgramDescriptionMessageID", "ExitProgramTextDescription",
                                        "Threadsafe", "MultithreadedJobAction", "QLMTTHDACNSystemValue", 
                                        "ExitProgramData"};
        String outputTableName = dbTempConnection.createTempTable("exitpgminfo", exitPgmTableColumns);

        /*
        EXTI0300 Format

        Offset 	Type 	Field
        Dec 	Hex
        0 	0 	BINARY(4) 	Bytes returned
        4 	4 	BINARY(4) 	Bytes available
        8 	8 	CHAR(16) 	Continuation handle
        24 	18 	BINARY(4) 	Offset to first exit program entry
        28 	1C 	BINARY(4) 	Number of exit program entries returned
        32 	20 	BINARY(4) 	Length of exit program entry
        36 	24 	CHAR(*) 	Reserved
        Note: Exit program entry information. These fields are repeated for each exit program entry returned.
                        BINARY(4) 	Offset to next exit program entry
                        CHAR(20) 	Exit point name
                        CHAR(8) 	Exit point format name
                        CHAR(1) 	Registered exit point
                        CHAR(1) 	Complete entry
                        CHAR(2) 	Reserved
                        BINARY(4) 	Exit program number
                        CHAR(10) 	Exit program name
                        CHAR(10) 	Exit program library name
                        CHAR(1) 	Exit program description indicator
                        CHAR(10) 	Exit program description message file name
                        CHAR(10) 	Exit program description message file library name
                        CHAR(7) 	Exit program description message ID
                        CHAR(50) 	Exit program text description
                        CHAR(2) 	Reserved
                        BINARY(4) 	Exit program data CCSID
                        BINARY(4) 	Offset to exit program data
                        BINARY(4) 	Length of exit program data	
                        CHAR(1) 	Threadsafe	
                        CHAR(1) 	Multithreaded job action	
                        CHAR(1) 	QMLTTHDACN system value	
                        CHAR(1) 	Reserved	
                        CHAR(*) 	Reserved	
                        CHAR(*) 	Exit program data
        */
        
        AS400DataType[] qusrtveiExitProgramDataType = new AS400DataType[]{
            new AS400Bin4(),	//Offset to next exit program entry
            new AS400Text(20),  //Exit point name
            new AS400Text(8),	//Exit point format name
            new AS400Text(1),   //Registered exit point
            new AS400Text(1),   //Complete entry
            new AS400Text(2),   //Reserved
            new AS400Bin4(),    //Exit program number
            new AS400Text(10),  //Exit program name
            new AS400Text(10),  //Exit program library name
            new AS400Text(1),   //Exit program description indicator
            new AS400Text(10),  //Exit program description message file name
            new AS400Text(10),  //Exit program description message file library name
            new AS400Text(7),   //Exit program description message ID
            new AS400Text(50),  //Exit program text description
            new AS400Text(2),   //Reserved
            new AS400Bin4(),    //Exit program data CCSID
            new AS400Bin4(),    //Offset to exit program data
            new AS400Bin4(),    //Length of exit program data
            new AS400Text(1),   //Threadsafe
            new AS400Text(1),   //Multithreaded job action
            new AS400Text(1),   //QMLTTHDACN system value
            new AS400Text(1)    //Reserved
            //followed by CHAR(*) - Reserved and CHAR(*) - Exit Program Data
        };
        
        AS400DataType[] qusrtveiHeaderDataType = new AS400DataType[]{
            new AS400Bin4(),    //Bytes returned            
            new AS400Bin4(),    //Bytes available
            new AS400Text(16),  //Continuation handle            
            new AS400Bin4(),    //Offset to first exit program entry
            new AS400Bin4(),    //Number of exit program entries returned
            new AS400Bin4()     //Length of exit program entry            
        };
        
        String handle = "                "; //For first call, must be 16 blanks
        
        do {
            ProgramParameter[] qusrtveiParms = new ProgramParameter[9];        
            qusrtveiParms[0] = new ProgramParameter(char16Converter.toBytes(handle));
            qusrtveiParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[1] = new ProgramParameter(65536);
            qusrtveiParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[2] = new ProgramParameter(bin4.toBytes(65536));
            qusrtveiParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[3] = new ProgramParameter(char8Converter.toBytes("EXTI0300"));
            qusrtveiParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[4] = new ProgramParameter(char20Converter.toBytes("*ALL                "));
            qusrtveiParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[5] = new ProgramParameter(char8Converter.toBytes("*ALL    "));
            qusrtveiParms[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[6] = new ProgramParameter(bin4.toBytes(-1));
            qusrtveiParms[6].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtveiParms[7] = new ProgramParameter(bin4.toBytes(0));
            qusrtveiParms[7].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            byte[] errorBytes = new byte[32];
            qusrtveiParms[8] = new ProgramParameter(errorBytes, 32);
            qusrtveiParms[8].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

            ProgramCall qusrtvei = new ProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qusrtvei.pgm", qusrtveiParms);   

            if (!qusrtvei.run()) {                            
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qusrtvei.getMessageList()));
                return null;
            }

            byte[] outputData = qusrtveiParms[1].getOutputData();
            
            AS400Structure returnedHeaderDataConverter = new AS400Structure(qusrtveiHeaderDataType);
            Object[] returnedHeader = (Object[]) returnedHeaderDataConverter.toObject(Arrays.copyOfRange(outputData, 0, IBMiUtilities.sumDataTypeFields(qusrtveiHeaderDataType)), 0);
            
            handle = returnedHeader[2].toString();
            
            // If not exit point data found in this list, do not process output (it's empty)
            int numEntries = (int)returnedHeader[4];
            if (numEntries == 0)
                break; 
                                    
            int entryOffset = (int)returnedHeader[3];

            AS400Structure returnedExitProgramDataConverter = new AS400Structure(qusrtveiExitProgramDataType);
            Object[] returnedExitProgram;            
            
            for (int i=0; i<numEntries; i++){
                returnedExitProgram = (Object[]) returnedExitProgramDataConverter.toObject(Arrays.copyOfRange(outputData, entryOffset, entryOffset + IBMiUtilities.sumDataTypeFields(qusrtveiExitProgramDataType)), 0);                

                Vector arrayData = new Vector();
                //Exit point name
                arrayData.addElement(returnedExitProgram[1].toString());
                //Exit point format name
                arrayData.addElement(returnedExitProgram[2].toString());
                //Registered exit point
                arrayData.addElement(returnedExitProgram[3].toString());
                //Complete entry
                arrayData.addElement(returnedExitProgram[4].toString());
                //Exit program number
                arrayData.addElement(String.valueOf((int)returnedExitProgram[6]));
                //Exit program name
                arrayData.addElement(returnedExitProgram[7].toString());
                //Exit program library name
                arrayData.addElement(returnedExitProgram[8].toString());
                //Exit program description indicator
                arrayData.addElement(returnedExitProgram[9].toString());
                //Exit program description message file name
                arrayData.addElement(returnedExitProgram[10].toString());
                //Exit program description message file library name
                arrayData.addElement(returnedExitProgram[11].toString());
                //Exit program description message ID
                arrayData.addElement(returnedExitProgram[12].toString());
                //Exit program text description
                arrayData.addElement(returnedExitProgram[13].toString());
                //Threadsafe
                arrayData.addElement(returnedExitProgram[18].toString());
                //Multithreaded job action
                arrayData.addElement(returnedExitProgram[19].toString());
                //QLMTTHDACN system value
                arrayData.addElement(returnedExitProgram[20].toString());
                //Exit program data
                arrayData.addElement((String)(new AS400Text((int)returnedExitProgram[16], (int)returnedExitProgram[15])).toObject(Arrays.copyOfRange(outputData, (int)returnedExitProgram[17], (int)returnedExitProgram[17] + (int)returnedExitProgram[16])));
                
                dbTempConnection.insertrow(outputTableName, arrayData);
                
                entryOffset = (int)returnedExitProgram[0];
            }
        } while (!handle.equals("                "));
        
        return outputTableName;        
    }

    
    public String getFunctionUsageInfo(String FunctionID) 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        return getFunctionUsageInfo("", FunctionID);
    }
    
    public String getFunctionUsageInfo(String tableName, String FunctionID) 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*

            Retrieve Function Usage Information (QSYRTFUI) API

              Required Parameter Group for QSYRTFUI:

            1 	Receiver variable 	Output 	Char(*)
            2 	Length of receiver variable 	Input 	Binary(4)
            3 	Format name 	Input 	Char(8)
            4 	Function ID 	Input 	Char(30)
            5 	Error code 	I/O 	Char(*)
        
        */
        
        AS400Text char8Converter = new AS400Text(8);
        AS400Text char30Converter = new AS400Text(30);    
        AS400Bin4 bin4 = new AS400Bin4(); 
        
        String[] functionUsageTableColumns = {"FunctionID", "UserProfileName", "UsageSetting", 
                                        "UserProfileType"};
        
        String outputTableName = (tableName.equals("") ? dbTempConnection.createTempTable("fcnusageinfo-" + FunctionID, functionUsageTableColumns) 
                                                  : tableName);

        /*
        FNUI0100 Format

        Offset 	Type 	Field
        Dec 	Hex
        0 	0 	BINARY(4) 	Bytes returned
        4 	4 	BINARY(4) 	Bytes available
        8 	8 	BINARY(4) 	Offset to first function usage entry
        12 	C 	BINARY(4) 	Number of function usage entries returned
        16 	10 	BINARY(4) 	Length of function usage entry
        20 	14 	CHAR(*) 	Reserved
        Function usage entry information. These fields are repeated for each function usage entry returned.
  	  	CHAR(10) 	User profile name
  	  	CHAR(1) 	Usage setting
  	  	CHAR(1) 	User profile type
  	  	CHAR(*) 	Reserved
        */
        
        AS400DataType[] qsyrtfuiFunctionUsageDataType = new AS400DataType[]{
            new AS400Text(10),	//User profile name
            new AS400Text(1),	//Usage setting
            new AS400Text(1),	//User profile type
            //followed by CHAR(*) - Reserved
        };
        
        AS400DataType[] qsyrtfuiHeaderDataType = new AS400DataType[]{
            new AS400Bin4(),    //Bytes returned            
            new AS400Bin4(),    //Bytes available
            new AS400Bin4(),    //Offset to first function usage entry
            new AS400Bin4(),    //Number of function usage entries returned
            new AS400Bin4()     //Length of function usage entry            
        };
        
        ProgramParameter[] qsyrtfuiParms = new ProgramParameter[5];        
        qsyrtfuiParms[0] = new ProgramParameter(65536);
        qsyrtfuiParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qsyrtfuiParms[1] = new ProgramParameter(bin4.toBytes(65536));
        qsyrtfuiParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qsyrtfuiParms[2] = new ProgramParameter(char8Converter.toBytes("FNUI0100"));
        qsyrtfuiParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qsyrtfuiParms[3] = new ProgramParameter(char30Converter.toBytes(FunctionID));
        qsyrtfuiParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        byte[] errorBytes = new byte[32];
        qsyrtfuiParms[4] = new ProgramParameter(errorBytes, 32);
        qsyrtfuiParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        ProgramCall qsyrtfui = new ProgramCall(secure ? secureConnection : insecureConnection,
                                  "/qsys.lib/qsyrtfui.pgm", qsyrtfuiParms);   
        if (!qsyrtfui.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qsyrtfui.getMessageList()));
            return null;
        }
        byte[] outputData = qsyrtfuiParms[0].getOutputData();
        
        AS400Structure returnedHeaderDataConverter = new AS400Structure(qsyrtfuiHeaderDataType);
        Object[] returnedHeader = (Object[]) returnedHeaderDataConverter.toObject(Arrays.copyOfRange(outputData, 0, IBMiUtilities.sumDataTypeFields(qsyrtfuiHeaderDataType)), 0);
                
        // If not exit point data found in this list, do not process output (it's empty)
        int numEntries = (int)returnedHeader[3];
        if (numEntries == 0)
            return null; 
                                
        int entryOffset = (int)returnedHeader[2];
        AS400Structure returnedFunctionUsageDetailsDataConverter = new AS400Structure(qsyrtfuiFunctionUsageDataType);
        Object[] returnedFunctionUsageDetails;            
            
        for (int i=0; i<numEntries; i++){
            returnedFunctionUsageDetails = (Object[]) returnedFunctionUsageDetailsDataConverter.toObject(Arrays.copyOfRange(outputData, entryOffset, entryOffset + IBMiUtilities.sumDataTypeFields(qsyrtfuiFunctionUsageDataType)), 0);                
            Vector arrayData = new Vector();
            //Function ID
            arrayData.addElement(FunctionID);
            //User profile name
            arrayData.addElement(returnedFunctionUsageDetails[0].toString());
            //Usage setting
            arrayData.addElement(returnedFunctionUsageDetails[1].toString());
            //User profile type
            arrayData.addElement(returnedFunctionUsageDetails[2].toString());
               
            dbTempConnection.insertrow(outputTableName, arrayData);
                
            entryOffset += (int)returnedHeader[4];
        }
        
        return outputTableName;        
    }
    
    public String getFunctionUsageInfo() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*

            Retrieve Function Information (QSYRTVFI) API

              Required Parameter Group for QSYRTVFI:

            1 	Continuation handle 	Input 	Char(20)
            2 	Receiver variable 	Output 	Char(*)
            3 	Length of receiver variable 	Input 	Binary(4)
            4 	Format name 	Input 	Char(8)
            5 	Function selection criteria 	Input 	Char(*)
            6 	Desired CCSID 	Input 	Binary(4)
            7 	Error code 	I/O 	Char(*)        
        */
        
        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Bin4 bin4 = new AS400Bin4(); 
        
        String[] functionUsageTableColumns = {"FunctionID", "FunctionCategory", "FunctionType", 
                                        "FunctionNameMessagefileName", "FunctionNameMessagefileLibraryName", 
                                        "FunctionNameMessageID", "FunctionNameMessageText", "FunctionName", 
                                        "FunctionDescriptionMessagefileName", 
                                        "FunctionDescriptionMessagefileLibraryName", 
                                        "FunctionDescriptionMessageID", "FunctionDescriptionMessageText", 
                                        "FunctionDescription", "FunctionProductID", "FunctionGroupID", 
                                        "DefaultUsage", "ALLOBJIndicator", "UsageInformationIndicator"};
        String outputTableName = dbTempConnection.createTempTable("fcnusageinfo", functionUsageTableColumns);

        String[] functionUsageDetailsTableColumns = {"FunctionID", "UserProfileName", "UsageSetting", 
                                        "UserProfileType"};
        String outputDetailsTableName = dbTempConnection.createTempTable("fcnusageinfodetails", functionUsageDetailsTableColumns);
        
        /*
        FCNI0100 Format

        Offset 	Type 	Field
        Dec 	Hex
        0 	0 	BINARY(4) 	Bytes returned
        4 	4 	BINARY(4) 	Bytes available
        8 	8 	CHAR(20) 	Continuation handle
        28 	1C 	BINARY(4) 	Offset to first function entry
        32 	20 	BINARY(4) 	Number of function entries returned
        36 	24 	BINARY(4) 	Length of function entry
        40 	28 	CHAR(*) 	Reserved
        Function entry information. These fields are repeated for each function entry returned.
  	  	CHAR(30) 	Function ID
  	  	CHAR(1) 	Function category
  	  	CHAR(1) 	Function type
  	  	CHAR(10) 	Function-name message-file name
  	  	CHAR(10) 	Function-name message-file library name
  	  	CHAR(7) 	Function-name message ID
  	  	CHAR(330) 	Function-name message text
  	  	CHAR(3) 	Reserved
  	  	BINARY(4) 	Function-name message-text CCSID
  	  	CHAR(330) 	Function name
  	  	CHAR(2) 	Reserved
  	  	BINARY(4) 	Function name CCSID
  	  	CHAR(10) 	Function-description message-file name
  	  	CHAR(10) 	Function-description message-file library name
  	  	CHAR(7) 	Function-description message ID
  	  	CHAR(330) 	Function-description message text
  	  	CHAR(3) 	Reserved
  	  	BINARY(4) 	Function-description message text CCSID
  	  	CHAR(330) 	Function description
  	  	CHAR(2) 	Reserved
  	  	BINARY(4) 	Function description CCSID
  	  	CHAR(30) 	Function product ID
  	  	CHAR(30) 	Function group ID
  	  	CHAR(1) 	Default usage
  	  	CHAR(1) 	*ALLOBJ indicator
  	  	CHAR(1) 	Usage information indicator
  	  	CHAR(*) 	Reserved
        */
        
        AS400DataType[] qsyrtvfiFunctionUsageDataType = new AS400DataType[]{
            new AS400Text(30),	//Function ID
            new AS400Text(1),	//Function category
            new AS400Text(1),	//Function type
            new AS400Text(10),	//Function-name message-file name
            new AS400Text(10),	//Function-name message-file library name
            new AS400Text(7),	//Function-name message ID
            new AS400Text(330),	//Function-name message text
            new AS400Text(3),	//Reserved
            new AS400Bin4(),	//Function-name message-text CCSID
            new AS400Text(330),	//Function name
            new AS400Text(2),	//Reserved
            new AS400Bin4(),	//Function name CCSID
            new AS400Text(10),	//Function-description message-file name
            new AS400Text(10),	//Function-description message-file library name
            new AS400Text(7),	//Function-description message ID
            new AS400Text(330),	//Function-description message text
            new AS400Text(3),	//Reserved
            new AS400Bin4(),	//Function-description message text CCSID
            new AS400Text(330),	//Function description
            new AS400Text(2),	//Reserved
            new AS400Bin4(),	//Function description CCSID
            new AS400Text(30),	//Function product ID
            new AS400Text(30),	//Function group ID
            new AS400Text(1),	//Default usage
            new AS400Text(1),	//*ALLOBJ indicator
            new AS400Text(1)	//Usage information indicator
            //followed by CHAR(*) - Reserved
        };
        
        AS400DataType[] qsyrtvfiHeaderDataType = new AS400DataType[]{
            new AS400Bin4(),    //Bytes returned            
            new AS400Bin4(),    //Bytes available
            new AS400Text(20),  //Continuation handle            
            new AS400Bin4(),    //Offset to first function entry
            new AS400Bin4(),    //Number of function entries returned
            new AS400Bin4()     //Length of function entry            
        };
        
        String handle = "                    "; //For first call, must be 20 blanks
        
        do {
            ProgramParameter[] qsyrtvfiParms = new ProgramParameter[7];        
            qsyrtvfiParms[0] = new ProgramParameter(char20Converter.toBytes(handle));
            qsyrtvfiParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qsyrtvfiParms[1] = new ProgramParameter(65536);
            qsyrtvfiParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qsyrtvfiParms[2] = new ProgramParameter(bin4.toBytes(65536));
            qsyrtvfiParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qsyrtvfiParms[3] = new ProgramParameter(char8Converter.toBytes("FCNI0100"));
            qsyrtvfiParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qsyrtvfiParms[4] = new ProgramParameter(bin4.toBytes(0));
            qsyrtvfiParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qsyrtvfiParms[5] = new ProgramParameter(bin4.toBytes(0));
            qsyrtvfiParms[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            byte[] errorBytes = new byte[32];
            qsyrtvfiParms[6] = new ProgramParameter(errorBytes, 32);
            qsyrtvfiParms[6].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

            ProgramCall qsyrtvfi = new ProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qsyrtvfi.pgm", qsyrtvfiParms);   

            if (!qsyrtvfi.run()) {                            
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qsyrtvfi.getMessageList()));
                return null;
            }

            byte[] outputData = qsyrtvfiParms[1].getOutputData();
            
            AS400Structure returnedHeaderDataConverter = new AS400Structure(qsyrtvfiHeaderDataType);
            Object[] returnedHeader = (Object[]) returnedHeaderDataConverter.toObject(Arrays.copyOfRange(outputData, 0, IBMiUtilities.sumDataTypeFields(qsyrtvfiHeaderDataType)), 0);
            
            handle = returnedHeader[2].toString();
            
            // If not exit point data found in this list, do not process output (it's empty)
            int numEntries = (int)returnedHeader[4];
            if (numEntries == 0)
                break; 
                                    
            int entryOffset = (int)returnedHeader[3];

            AS400Structure returnedFunctionUsageDataConverter = new AS400Structure(qsyrtvfiFunctionUsageDataType);
            Object[] returnedFunctionUsage;            
            
            for (int i=0; i<numEntries; i++){
                returnedFunctionUsage = (Object[]) returnedFunctionUsageDataConverter.toObject(Arrays.copyOfRange(outputData, entryOffset, entryOffset + IBMiUtilities.sumDataTypeFields(qsyrtvfiFunctionUsageDataType)), 0);                

                Vector arrayData = new Vector();
                //Function ID
                arrayData.addElement(returnedFunctionUsage[0].toString());
                //Function category
                arrayData.addElement(returnedFunctionUsage[1].toString());
                //Function type
                arrayData.addElement(returnedFunctionUsage[2].toString());
                //Function-name message-file name
                arrayData.addElement(returnedFunctionUsage[3].toString());
                //Function-name message-file library name
                arrayData.addElement(returnedFunctionUsage[4].toString());
                //Function-name message ID
                arrayData.addElement(returnedFunctionUsage[5].toString());
                //Function-name message text
                arrayData.addElement(returnedFunctionUsage[6].toString());
                //Function name
                arrayData.addElement(returnedFunctionUsage[9].toString());
                //Function-description message-file name
                arrayData.addElement(returnedFunctionUsage[12].toString());
                //Function-description message-file library name
                arrayData.addElement(returnedFunctionUsage[13].toString());
                //Function-description message ID
                arrayData.addElement(returnedFunctionUsage[14].toString());
                //Function-description message text
                arrayData.addElement(returnedFunctionUsage[15].toString());
                //Function description
                arrayData.addElement(returnedFunctionUsage[18].toString());
                //Function product ID
                arrayData.addElement(returnedFunctionUsage[21].toString());
                //Function group ID
                arrayData.addElement(returnedFunctionUsage[22].toString());
                //Default usage
                arrayData.addElement(returnedFunctionUsage[23].toString());
                //*ALLOBJ indicator
                arrayData.addElement(returnedFunctionUsage[24].toString());
                //Usage information indicator
                arrayData.addElement(returnedFunctionUsage[25].toString());
                
                dbTempConnection.insertrow(outputTableName, arrayData);

                //Get function usage details per function if it is an administrable function (Function Type=3)
                if (returnedFunctionUsage[2].toString().equals("3"))
                  getFunctionUsageInfo(outputDetailsTableName, returnedFunctionUsage[0].toString());
                
                entryOffset += (int)returnedHeader[5];
            }
        } while (!handle.equals("                    "));

        String viewName = "fcnusagecomplete" + new SimpleDateFormat("YYMMddHHmmSS").format(new Date());
        dbTempConnection.query("CREATE VIEW " + viewName + " AS SELECT "
                                + outputTableName + ".FunctionID, FunctionCategory, FunctionType, "
                                + "FunctionNameMessagefileName, FunctionNameMessagefileLibraryName, FunctionNameMessageID, "
                                + "FunctionNameMessageText, FunctionName, FunctionDescriptionMessagefileName, "
                                + "FunctionDescriptionMessagefileLibraryName, FunctionDescriptionMessageID, "
                                + "FunctionDescriptionMessageText, FunctionDescription, FunctionProductID, "
                                + "FunctionGroupID, DefaultUsage, ALLOBJIndicator, UsageInformationIndicator, "
                                + "UserProfileName, UsageSetting, UserProfileType FROM "
                                + outputTableName + " LEFT OUTER JOIN " + outputDetailsTableName + " ON "
                                + outputTableName + ".FunctionID = "
                                + outputDetailsTableName + ".FunctionID");
               
        return viewName;        
    }
            
    public String getNetStat() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*
    
            List Network Connections (QtocLstNetCnn) API
            Required Parameter Group:

          1	Qualified user space name           Input	Char(20)
          2	Format name                         Input	Char(8)
          3	Connection list qualifier           Input	Char(*)
          4	Connection list qualifier size      Input	Binary(4)
          5	Connection list qualifier format    Input	Char(8)
          6	Error Code                          I/O         Char(*)
           
        
        */

        
        createUserSpace("NETSTAT", curLib, "NETSTAT", 1, "NETSTAT user space");
        if (!makeUserSpaceAutoExtendible("NETSTAT", curLib, true))
            return null;

        String userSpaceName = IBMiUtilities.padTrimString("NETSTAT   " + curLib.toUpperCase(), 20);

        ProgramParameter[] qtocnetstsParms = new ProgramParameter[6];

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Text char64Converter = new AS400Text(64); 
        AS400Bin4 bin4 = new AS400Bin4();                                                                        
        
        qtocnetstsParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
        qtocnetstsParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[1] = new ProgramParameter(char8Converter.toBytes("NCNN0100"));
        qtocnetstsParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[2] = new ProgramParameter(char64Converter.toBytes(
                /*
                NCLQ0100 Format
                Offset	Type	Field
                Dec	Hex
                0	0	CHAR(10)	Net connection type
                10	A	CHAR(10)	List request type
                20	14	CHAR(12)	Reserved
                32	20	BINARY(4)	Local internet address lower value
                36	24	BINARY(4)	Local internet address upper value
                40	28	BINARY(4)	Local port lower value
                44	2C	BINARY(4)	Local port upper value
                48	30	BINARY(4)	Remote internet address lower value
                52	34	BINARY(4)	Remote internet address upper value
                56	38	BINARY(4)	Remote port lower value
                60	3C	BINARY(4)	Remote port upper value                
                */        
                                    "*ALL      " +                 
                                    "*ALL      " +
                                    new String(new byte[] {0x00,0x00,0x00,0x00, 
                                                           0x00,0x00,0x00,0x00, 
                                                           0x00,0x00,0x00,0x00}) +                                             
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}) +
                                    new String(new byte[] {0x00,0x00,0x00,0x00}))); 
        qtocnetstsParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);        
        qtocnetstsParms[3] = new ProgramParameter(bin4.toBytes(new Integer(64)));
        qtocnetstsParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[4] = new ProgramParameter(char8Converter.toBytes("NCLQ0100"));
        qtocnetstsParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        byte[] errorBytes = new byte[32];
        qtocnetstsParms[5] = new ProgramParameter(errorBytes, 32);
        qtocnetstsParms[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ServiceProgramCall qtocnetsts = new ServiceProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qtocnetsts.srvpgm", "QtocLstNetCnn",
                                        ServiceProgramCall.NO_RETURN_VALUE, qtocnetstsParms);                                
        if (!qtocnetsts.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qtocnetsts.getMessageList()));
            return null;
        }
        
        /*
        NCNN0100 Format

        Offset	Type	Field
        Dec	Hex
        0	0	CHAR(15)	Remote address
        15	F	CHAR(1)         Reserved
        16	10	BINARY(4)	Remote address binary
        20	14	CHAR(15)	Local address
        35	23	CHAR(1)         Reserved
        36	24	BINARY(4)	Local address binary
        40	28	BINARY(4)	Remote port
        44	2C	BINARY(4)	Local port
        48	30	BINARY(4)	TCP state
        52	34	BINARY(4)	Idle time in milliseconds
        56	38	BINARY(8)	Bytes in
        64	40	BINARY(8)	Bytes out
        72	48	BINARY(4)	Connection open type
        76	4C	CHAR(10)	Net connection type
        86	56	CHAR(2)         Reserved
        88	58	CHAR(10)	Associated user profile
        98	62	CHAR(2)         Reserved
        */
        
        AS400DataType[] netstatDataType = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),     
            new AS400Bin4(),   
            new AS400Bin8(),            
            new AS400Bin8(),        
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(2),
            new AS400Text(10),
            new AS400Text(2)
        };
        
        return retrieveUserSpace("NETSTAT", curLib, netstatDataType);
    }

    public String getARPTable() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{

        String netIfacesTableName = getNetIfaces();
        
        if ((insecureConnection==null && secureConnection==null) || netIfacesTableName == null)
            return null;
        DefaultTableModel lineNames = dbTempConnection.query("SELECT DISTINCT _7 FROM " + netIfacesTableName + " WHERE _7 NOT LIKE \"*%\" AND _7 NOT LIKE \"\" AND _7 NOT NULL").toTableModel();
        String[] arpTables = new String[lineNames.getRowCount()];
        for (int i=0; i<lineNames.getRowCount(); i++){
            arpTables[i] = getARPTable(lineNames.getValueAt(i, 0).toString());
        }        
        return dbTempConnection.unionTempTables(arpTables);
    }
    
    public String getARPTable(String lineName) 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*
    
            List Physical Interface ARP Table (QtocLstPhyIfcARPTbl) API
            Required Parameter Group:

                1 	Qualified user space name 	Input 	Char(20)
                2 	Format name                     Input 	Char(8)
                3 	Line name                       Input 	Char(10)
                4 	Error Code                      I/O 	Char(*)

        
        */

        
        createUserSpace("ARPTABLE", curLib, "ARPTABLE", 1, "ARPTABLE user space");
        if (!makeUserSpaceAutoExtendible("ARPTABLE", curLib, true))
            return null;

        String userSpaceName = IBMiUtilities.padTrimString("ARPTABLE  " + curLib.toUpperCase(), 20);

        ProgramParameter[] qtocnetstsParms = new ProgramParameter[4];

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Text char10Converter = new AS400Text(10); 
        
        qtocnetstsParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
        qtocnetstsParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[1] = new ProgramParameter(char8Converter.toBytes("ARPT0100"));
        qtocnetstsParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[2] = new ProgramParameter(char10Converter.toBytes(IBMiUtilities.padTrimString(lineName, 10)));
        qtocnetstsParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);        
        byte[] errorBytes = new byte[32];
        qtocnetstsParms[3] = new ProgramParameter(errorBytes, 32);
        qtocnetstsParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ServiceProgramCall qtocnetsts = new ServiceProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qtocnetsts.srvpgm", "QtocLstPhyIfcARPTbl",
                                        ServiceProgramCall.NO_RETURN_VALUE, qtocnetstsParms);                                
        if (!qtocnetsts.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qtocnetsts.getMessageList()));
            return null;
        }
        
        /*
            ARPT0100 Format

            Offset 	Type            Field
            Dec 	Hex
            0 	0 	CHAR(15) 	Internet address
            15 	F 	CHAR(1) 	Reserved
            16 	10 	BINARY(4) 	Internet address binary
            20 	14 	BINARY(4) 	Line type
            24 	18 	BINARY(4) 	Ethernet type
            28 	1C 	BINARY(4) 	Type of entry
            32 	20 	BINARY(4) 	Data link connection identifier (DLCI)
            36 	24 	BINARY(4) 	Routing information field (RIF) valid mask
            40 	28 	CHAR(18) 	Routing information field (RIF)
            58 	3A 	CHAR(17) 	Physical address
            75 	4B 	CHAR(1) 	Reserved
        From V7R2:
            76 	4C 	CHAR(10) 	Line name
            86 	56 	CHAR(2) 	Reserved
            88 	58 	BINARY(4) 	Virtual LAN identifier 
        */
        
        AS400DataType[] arptableDataTypeV7R1 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(18),
            new AS400Text(17),
            new AS400Text(1)
        };

        AS400DataType[] arptableDataTypeV7R2 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(18),
            new AS400Text(17),
            new AS400Text(1),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4()           
        };
        
        if ((secure ? secureConnection : insecureConnection).getVRM() <= 0x00070100)
           return retrieveUserSpace("ARPTABLE", curLib, arptableDataTypeV7R1);
        else if ((secure ? secureConnection : insecureConnection).getVRM() > 0x00070100)
           return retrieveUserSpace("NETROUTE", curLib, arptableDataTypeV7R2);
        else
           return null;
    }

    public String getSMBShares() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*
        
        List Server Information (QZLSLSTI) API

          Required Parameter Group:

        1 	Qualified user space name 	Input 	Char(20)
        2 	Format                          Input 	Char(8)
        3 	Information qualifier           Input 	Char(15)
        4 	Error code                      I/O 	Char(*)

          Optional Parameter 1:

        5 	Session user                    Input 	Char(10)

          Optional Parameter 2:

        6 	Expanded workstation name 	Input 	Char(*) 
        
        */

        
        createUserSpace("SMBSHARES", curLib, "SMBSHARES", 1, "SMBSHARES user space");
        if (!makeUserSpaceAutoExtendible("SMBSHARES", curLib, true))
            return null;

        String userSpaceName = IBMiUtilities.padTrimString("SMBSHARES " + curLib.toUpperCase(), 20);

        ProgramParameter[] qzlslstiParms = new ProgramParameter[4];

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Text char15Converter = new AS400Text(15); 
        AS400Bin4 bin4 = new AS400Bin4();                                                                        
        
        qzlslstiParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
        qzlslstiParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qzlslstiParms[1] = new ProgramParameter(char8Converter.toBytes("ZLSL0100"));
        qzlslstiParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qzlslstiParms[2] = new ProgramParameter(char15Converter.toBytes("*ALL           ")); 
        qzlslstiParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);        
        byte[] errorBytes = new byte[32];
        qzlslstiParms[3] = new ProgramParameter(errorBytes, 32);
        qzlslstiParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ProgramCall qzlslsti = new ProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qzlslsti.pgm", qzlslstiParms);                                
        if (!qzlslsti.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qzlslsti.getMessageList()));
            return null;
        }
        
        /*
            ZLSL0100 Format
        
           Offset 	Type            Field
           Dec 	Hex
           0 	0 	BINARY(4) 	Length of this entry
           4 	4 	CHAR(12) 	Share name
           16 	10 	BINARY(4) 	Device type
           20 	14 	BINARY(4) 	Permissions
           24 	18 	BINARY(4) 	Maximum users
           28 	1C 	BINARY(4) 	Current users
           32 	20 	BINARY(4) 	Spooled file type
           36 	24 	BINARY(4) 	Offset to path name
           40 	28 	BINARY(4) 	Length of path name
           44 	2C 	CHAR(20) 	Qualified output queue
           64 	40 	CHAR(50) 	Print driver type
           114 	72 	CHAR(50) 	Text description
           164 	A4 	CHAR(*) 	Path name
        */
        
        AS400DataType[] qzlslstiDataType = new AS400DataType[]{
            new AS400Bin4(),            
            new AS400Text(12),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(20),
            new AS400Text(50),
            new AS400Text(50),
            new AS400Text(1024)
        };
        return retrieveUserSpace("SMBSHARES", curLib, qzlslstiDataType);
    }
    
    public String getNFSShares() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{
        
        if (insecureConnection==null && secureConnection==null)
            return null;

        /*
        
        Retrieve Network File System Export Entries (QZNFRTVE) API

          Required Parameter Group:

        1 	Receiver variable                       Output 	Char(*)
        2 	Length of receiver variable in bytes 	Input 	Binary(4)
        3 	Returned records feedback information 	Output 	Char(16)
        4 	Format name                             Input 	Char(8)
        5 	Object path name                        Input 	Char(*)
        6 	Length of object path name in bytes 	Input 	Binary(4)
        7 	CCSID of object path name given 	Input 	Binary(4)
        8 	Desired CCSID of the object path
                names returned                          Input 	Binary(4)
        9 	Handle                                  Input 	Binary(4)
        10 	Error code                              I/O 	Char(*) 
        
        */
        

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char6Converter = new AS400Text(6);    
        AS400Bin4 bin4 = new AS400Bin4(); 

        /*
        Currently, while the EXPE0100 format is quite extensive, only the basic NFS share information
        will be read (read only flag, SUID flag, anonymous user profile name, NFS version, NFS4 root export flag, NFS4 public export flag, object path name).
        */
        
        String[] nfsTableColumns = {"IsReadOnly", "IsNoSUID", "AnonymousUserName", "NFSVersion", "IsNFS4Root", "IsNFS4Public", "ObjectPathName"};
        String outputTableName = dbTempConnection.createTempTable("nfsshares", nfsTableColumns);

        /*
            EXPE0100 Format
        
            Offset 	Type            Field
            Dec 	Hex
            0 	0 	BINARY(4) 	Length of entry
            4 	4 	BINARY(4) 	Displacement to object path name
            8 	8 	BINARY(4) 	Length of object path name
            12 	C 	BINARY(4) 	CCSID of object path name
            16 	10 	BINARY(4) 	Read-only flag
            20 	14 	BINARY(4) 	NOSUID flag
            24 	18 	BINARY(4) 	Displacement to read-write host names
            28 	1C 	BINARY(4) 	Number of read-write host names
            32 	20 	BINARY(4) 	Displacement to root host names
            36 	24 	BINARY(4) 	Number of root host names
            40 	28 	BINARY(4) 	Displacement to access host names
            44 	2C 	BINARY(4) 	Number of access host names
            48 	30 	BINARY(4) 	Displacement to host options
            52 	34 	BINARY(4) 	Number of host options
            56 	38 	BINARY(4) 	Anonymous user ID
            60 	3C 	CHAR(10) 	Anonymous User Profile
        From V6R1:
            70 	46 	BINARY(4) 	NFS version flag
            74 	4A 	BINARY(4) 	Displacement to NFS security flavors
            78 	4E 	BINARY(4) 	Number of security flavors
            82 	52 	BINARY(4) 	NFS Root export flag
            86 	56 	BINARY(4) 	Public export flag
            90 	5A 	BINARY(4) 	Displacement to export name
            94 	5E 	BINARY(4) 	Length of export name
            98 	62 	BINARY(4) 	CCSID of export name
        End From V6R1
            * 	* 	CHAR(*) 	Object path name
        From V6R1:
            * 	* 	CHAR(*) 	Export name
            These fields repeat for each NFS security flavor. 	
                        BINARY(4) 	Security flavor
        End From V6R1
            These fields repeat for each host name in the read-write access list:
                        BINARY(4) 	Length of host name entry
                        BINARY(4) 	Length of host name
                        CHAR(*) 	Host name
            These fields repeat for each host name in the root access list. 	
                        BINARY(4) 	Length of host name entry
                        BINARY(4) 	Length of host name
                        CHAR(*) 	Host name
            These fields repeat for each host name in the access list. 	
                        BINARY(4) 	Length of host name entry
                        BINARY(4) 	Length of host name
                        CHAR(*) 	Host name
            These fields repeat for each host name in the host options list. 	
                        BINARY(4) 	Length of host name options entry
                        BINARY(4) 	Network data file CCSID
                        BINARY(4) 	Network path name CCSID
                        BINARY(4) 	Write mode flag
                        BINARY(4) 	Length of host name
                        CHAR(*) 	Host name
        */
        
        AS400DataType[] qznfrtveCommonDataType = new AS400DataType[]{
            new AS400Bin4(),    //Length of entry            
            new AS400Bin4(),    //Displacement to object path name        
            new AS400Bin4(),    //Length of object path name        
            new AS400Bin4(),    //CCSID of object path name        
            new AS400Bin4(),    //Read-only flag        
            new AS400Bin4(),    //NOSUID flag        
            new AS400Bin4(),    //Displacement to read-write host names        
            new AS400Bin4(),    //Number of read-write host names        
            new AS400Bin4(),    //Displacement to root host names        
            new AS400Bin4(),    //Number of root host names        
            new AS400Bin4(),    //Displacement to access host names        
            new AS400Bin4(),    //Number of access host names        
            new AS400Bin4(),    //Displacement to host options        
            new AS400Bin4(),    //Number of host options        
            new AS400Bin4(),    //Anonymous user ID        
            new AS400Text(10)   //Anonymous User Profile
        };

        AS400DataType[] qznfrtveV6R1DataType = new AS400DataType[]{
            new AS400Bin4(),    //NFS version flag        
            new AS400Bin4(),    //Displacement to NFS security flavors        
            new AS400Bin4(),    //Number of security flavors        
            new AS400Bin4(),    //NFS Root export flag        
            new AS400Bin4(),    //Public export flag        
            new AS400Bin4(),    //Displacement to export name        
            new AS400Bin4(),    //Length of export name        
            new AS400Bin4()     //CCSID of export name       
        };

        
        AS400DataType[] qznfrtveFeedBackDataType = new AS400DataType[]{
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4()            
        };
        
        int handle = 0;
        byte[] buffer;
        Object[] convertedBuffer;
        AS400Structure bufferConverter;
        
        do {
            ProgramParameter[] qznfrtveParms = new ProgramParameter[10];        
            qznfrtveParms[0] = new ProgramParameter(65536);
            qznfrtveParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[1] = new ProgramParameter(bin4.toBytes(65536));
            qznfrtveParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[2] = new ProgramParameter(16); 
            qznfrtveParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);        
            qznfrtveParms[3] = new ProgramParameter(char8Converter.toBytes("EXPE0100"));
            qznfrtveParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[4] = new ProgramParameter(char6Converter.toBytes("*FIRST"));
            qznfrtveParms[4].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[5] = new ProgramParameter(bin4.toBytes(6));
            qznfrtveParms[5].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[6] = new ProgramParameter(bin4.toBytes(0));
            qznfrtveParms[6].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[7] = new ProgramParameter(bin4.toBytes(0));
            qznfrtveParms[7].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qznfrtveParms[8] = new ProgramParameter(bin4.toBytes(handle));
            qznfrtveParms[8].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            byte[] errorBytes = new byte[32];
            qznfrtveParms[9] = new ProgramParameter(errorBytes, 32);
            qznfrtveParms[9].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

            ProgramCall qznfrtve = new ProgramCall(secure ? secureConnection : insecureConnection,
                                            "/qsys.lib/qznfrtve.pgm", qznfrtveParms);   

            if (!qznfrtve.run()) {                            
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qznfrtve.getMessageList()));
                return null;
            }
            
            AS400Structure returnedFeedBackDataConverter = new AS400Structure(qznfrtveFeedBackDataType);
            Object[] returnedFeedBackArray = (Object[]) returnedFeedBackDataConverter.toObject(qznfrtveParms[2].getOutputData(), 0);
            if (returnedFeedBackArray.length != qznfrtveFeedBackDataType.length) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Received data format does not match.");
                return null;
            }
            
            handle = (int)returnedFeedBackArray[3];
            
            // If not NFS shares found in this list, do not process output (it's empty)
            int numEntries = (int)returnedFeedBackArray[2];
            if (numEntries == 0)
                break; 
            
            
            byte[] outputData = qznfrtveParms[0].getOutputData();
            
            int entryLength; 
            int entryOffset = 0;
            
            ByteArrayInputStream dataStream;
            
            for (int i=0; i<numEntries; i++){
                entryLength = ByteBuffer.wrap(outputData, entryOffset, 4).getInt();
                dataStream = new ByteArrayInputStream(outputData, entryOffset, entryLength);
                
                buffer = new byte[IBMiUtilities.sumDataTypeFields(qznfrtveCommonDataType)]; 
                dataStream.read(buffer);

                bufferConverter = new AS400Structure(qznfrtveCommonDataType);
                convertedBuffer = (Object[]) bufferConverter.toObject(buffer, 0);
                
                int objectNameOffset = (int)convertedBuffer[1];
                int objectNameLength = (int)convertedBuffer[2];
                
                Vector arrayData = new Vector();
                //read only flag
                arrayData.addElement(String.valueOf((int)convertedBuffer[4]));
                //SUID flag
                arrayData.addElement(String.valueOf((int)convertedBuffer[5]));
                //anonymous user profile name
                arrayData.addElement(convertedBuffer[15].toString());
                
                if ((secure ? secureConnection : insecureConnection).getVRM() < 0x00060100){
                    arrayData.addElement("N/A");
                    arrayData.addElement("N/A");
                    arrayData.addElement("N/A");
                } else {
                    buffer = new byte[IBMiUtilities.sumDataTypeFields(qznfrtveV6R1DataType)]; 
                    dataStream.read(buffer);
                    bufferConverter = new AS400Structure(qznfrtveV6R1DataType);
                    convertedBuffer = (Object[]) bufferConverter.toObject(buffer, 0);
                    
                    //NFS Version
                    arrayData.addElement(String.valueOf((int)convertedBuffer[0]));
                    //NFS4 root export flag
                    arrayData.addElement(String.valueOf((int)convertedBuffer[3]));
                    //NFS4 public export flag
                    arrayData.addElement(String.valueOf((int)convertedBuffer[4]));
                }
                dataStream.reset();
                dataStream.skip(objectNameOffset);
                byte[] objectName = new byte[objectNameLength];
                dataStream.read(objectName);
                //object path name        
                arrayData.addElement((String)(new AS400Text(objectNameLength)).toObject(objectName));

                /*
                For future development, the indication following may be implemented:
                - security flavors
                - read-write access list
                - root access list
                - access list
                - host options list
                */
                dbTempConnection.insertrow(outputTableName, arrayData);
                
                entryOffset += entryLength;
            }
        } while (handle != 0);
        
        return outputTableName;        
    }
    
    public String getNetRoutes() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{

        /*
    
            List Network Routes (QtocLstNetRte) API
            Required Parameter Group:

              1 	Qualified user space name 	Input 	Char(20)
              2 	Format name                     Input 	Char(8)
              3 	Error Code                      I/O 	Char(*)
        
        */

        
        createUserSpace("NETROUTE", curLib, "NETROUTE", 1, "User space for network routes");
        if (!makeUserSpaceAutoExtendible("NETROUTE", curLib, true))
            return null;

        String userSpaceName = IBMiUtilities.padTrimString("NETROUTE  " + curLib.toUpperCase(), 20);

        ProgramParameter[] qtocnetstsParms = new ProgramParameter[3];

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Bin4 bin4 = new AS400Bin4();                                                                        
        
        qtocnetstsParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
        qtocnetstsParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[1] = new ProgramParameter(char8Converter.toBytes("NRTE0100"));
        qtocnetstsParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        byte[] errorBytes = new byte[32];
        qtocnetstsParms[2] = new ProgramParameter(errorBytes, 32);
        qtocnetstsParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ServiceProgramCall qtocnetsts = new ServiceProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qtocnetsts.srvpgm", "QtocLstNetRte",
                                        ServiceProgramCall.NO_RETURN_VALUE, qtocnetstsParms);                                
        if (!qtocnetsts.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qtocnetsts.getMessageList()));
            return null;
        }
        
        /*
            NRTE0100 Format

                Offset 	Type 	Field
                Dec 	Hex
                0 	0 	CHAR(15) 	Route destination
                15 	F 	CHAR(1) 	Reserved
                16 	10 	BINARY(4) 	Route destination binary
                20 	14 	CHAR(15) 	Subnet mask
                35 	23 	CHAR(1) 	Reserved
                36 	24 	BINARY(4) 	Subnet mask binary
                40 	28 	CHAR(15) 	Next hop
                55 	37 	CHAR(1) 	Reserved
                56 	38 	BINARY(4) 	Next hop binary
                60 	3C 	BINARY(4) 	Route status
                64 	40 	BINARY(4) 	Type of service
                68 	44 	BINARY(4) 	Route MTU
                72 	48 	BINARY(4) 	Route type
                76 	4C 	BINARY(4) 	Route source
                80 	50 	BINARY(4) 	Route precedence
                84 	54 	BINARY(4) 	Local binding interface status
                88 	58 	BINARY(4) 	Local binding type
                92 	5C 	BINARY(4) 	Local binding line type
                96 	60 	CHAR(15) 	Local binding interface
                111 	6F 	CHAR(1) 	Reserved
                112 	70 	BINARY(4) 	Local binding interface binary
                116 	74 	CHAR(15) 	Local binding subnet mask
                131 	83 	CHAR(1) 	Reserved
                132 	84 	BINARY(4) 	Local binding subnet mask binary
                136 	88 	CHAR(15) 	Local binding network address
                151 	97 	CHAR(1) 	Reserved
                152 	98 	BINARY(4) 	Local binding network address binary
                156 	9C 	CHAR(10) 	Local binding line description
                166 	A6 	CHAR(8) 	Change date
                174 	AE 	CHAR(6) 	Change time
FROM V6R1:      180 	B4 	CHAR(50) 	Text description
                230 	E6 	CHAR(2) 	Reserved
FROM V7R2:      232 	E8 	BINARY(4) 	Local binding virtual LAN identifier
        */
        
        AS400DataType[] routesDataTypeV5R4 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(10),
            new AS400Text(8),
            new AS400Text(6)
        };
        
        AS400DataType[] routesDataTypeV6R1 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(10),
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(50),
            new AS400Text(2)
        };
        
        AS400DataType[] routesDataTypeV7R2 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),
            new AS400Text(10),
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4()
        };
        
        if ((secure ? secureConnection : insecureConnection).getVRM() < 0x00060100)
           return retrieveUserSpace("NETROUTE", curLib, routesDataTypeV5R4);
        else if ((secure ? secureConnection : insecureConnection).getVRM() < 0x00070200)
           return retrieveUserSpace("NETROUTE", curLib, routesDataTypeV6R1);
        else if ((secure ? secureConnection : insecureConnection).getVRM() >= 0x00070200)
           return retrieveUserSpace("NETROUTE", curLib, routesDataTypeV7R2);
        else return null;
    }    
    
    public String getNetIfaces() 
            throws PropertyVetoException, AS400SecurityException, 
            ErrorCompletingRequestException, IOException, InterruptedException, 
            ObjectDoesNotExistException, SQLException{

        /*
    
            List Network Interfaces (QtocLstNetIfc) API
            Required Parameter Group:

            1 	Qualified user space name 	Input 	Char(20)
            2 	Format name 	Input 	Char(8)
            3 	Error Code 	I/O 	Char(*)
        
        */
        
        createUserSpace("NETIFAC", curLib, "NETIFAC", 1, "User space for network interfaces");
        
        if (!makeUserSpaceAutoExtendible("NETIFAC", curLib, true))
            return null;

        String userSpaceName = IBMiUtilities.padTrimString("NETIFAC   " + curLib.toUpperCase(), 20);

        ProgramParameter[] qtocnetstsParms = new ProgramParameter[3];

        AS400Text char8Converter = new AS400Text(8);
        AS400Text char20Converter = new AS400Text(20);    
        AS400Bin4 bin4 = new AS400Bin4();                                                                        
        
        qtocnetstsParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName));
        qtocnetstsParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        qtocnetstsParms[1] = new ProgramParameter(char8Converter.toBytes("NIFC0100"));
        qtocnetstsParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
        byte[] errorBytes = new byte[32];
        qtocnetstsParms[2] = new ProgramParameter(errorBytes, 32);
        qtocnetstsParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);

        ServiceProgramCall qtocnetsts = new ServiceProgramCall(secure ? secureConnection : insecureConnection,
                                        "/qsys.lib/qtocnetsts.srvpgm", "QtocLstNetIfc",
                                        ServiceProgramCall.NO_RETURN_VALUE, qtocnetstsParms);                                
        if (!qtocnetsts.run()) {                            
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qtocnetsts.getMessageList()));
            return null;
        }
        
        /*
            NIFC0100 Format

            Offset 	Type 	Field
            Dec 	Hex
            0           0 	CHAR(15) 	Internet address
            15          F 	CHAR(1) 	Reserved
            16          10 	BINARY(4) 	Internet address binary
            20          14 	CHAR(15) 	Network address
            35          23 	CHAR(1) 	Reserved
            36          24 	BINARY(4) 	Network address binary
            40          28 	CHAR(10) 	Network name
            50          32 	CHAR(10) 	Line description
            60          3C 	CHAR(10) 	Interface name
            70          46 	CHAR(2) 	Reserved
            72          48 	BINARY(4) 	Interface status
            76          4C 	BINARY(4) 	Interface type of service
            80          50 	BINARY(4) 	Interface MTU
            84          54 	BINARY(4) 	Interface line type
            88          58 	CHAR(15) 	Host address
            103 	67 	CHAR(1) 	Reserved
            104 	68 	BINARY(4) 	Host address binary
            108 	6C 	CHAR(15) 	Interface subnet mask
            123 	7B 	CHAR(1) 	Reserved
            124 	7C 	BINARY(4) 	Interface subnet mask binary
            128 	80 	CHAR(15) 	Directed broadcast address
            143 	8F 	CHAR(1) 	Reserved
            144 	90 	BINARY(4) 	Directed broadcast address binary
            148 	94 	CHAR(8) 	Change date
            156 	9C 	CHAR(6) 	Change time
            162 	A2 	CHAR(15) 	Associated local interface
            177 	B1 	CHAR(3) 	Reserved
            180 	B4 	BINARY(4) 	Associated local interface binary
            184 	B8 	BINARY(4) 	Change status
            188 	BC 	BINARY(4) 	Packet rules
            192 	C0 	BINARY(4) 	Automatic start
            196 	C4 	BINARY(4) 	TRLAN bit sequencing
            200 	C8 	BINARY(4) 	Interface type
            204 	CC 	BINARY(4) 	Proxy ARP enabled
            208 	D0 	BINARY(4) 	Proxy ARP allowed
            212 	D4 	BINARY(4) 	Configured MTU
            216 	D8 	CHAR(24) 	Network name - full
            240 	F0 	CHAR(24) 	Interface name - full
        From V5R4:
            264 	108 	CHAR(50) 	Alias name
            314 	13A 	CHAR(2) 	Reserved
            316 	13C 	BINARY(4) 	Alias name CCSID
            320 	140 	BINARY(4) 	Offset to preferred interface list
            324 	144 	BINARY(4) 	Number of entries in preferred interface list
            328 	148 	BINARY(4) 	Length of one preferred interface list entry
            332 	14C 	CHAR(50) 	Interface description
            382 	17E 	CHAR(2) 	Reserved
            384 	180 	BINARY(4) 	DHCP created
            388 	184 	BINARY(4) 	DHCP dynamic DNS updates
            392 	188 	BINARY(8) 	DHCP lease expiration
            400 	190 	CHAR(8) 	DHCP lease expiration - date
            408 	198 	CHAR(6) 	DHCP lease expiration - time 
            x            	CHAR(*) 	Prefered interface list entry (See Format of Prefered Interface List Entry for more information )
        From V7R1:
            414 	19E 	BINARY(8) 	DHCP lease obtained
            422 	1A6 	CHAR(8) 	DHCP lease obtained - date
            430 	1AE 	CHAR(6) 	DHCP lease obtained - time
            436 	1B4 	CHAR(1) 	Reserved
            x            	CHAR(*) 	Prefered interface list entry (See Format of Prefered Interface List Entry for more information )
        End-From V7R1
        
        From V7R2:
            436 	1B4 	BINARY(4) 	Use DHCP unique identifier
            440 	1B8 	CHAR(15) 	DHCP server IP address
            455 	1C7 	CHAR(1) 	Reserved
            456 	1C8 	BINARY(4) 	Virtual LAN identifier
            460 	1CC 	BINARY(4) 	Preferred interface default route 
            x            	CHAR(*) 	Prefered interface list entry (See Format of Prefered Interface List Entry for more information )
        End-From V7R2
        
            x            	CHAR(*) 	Prefered interface list entry (See Format of Prefered Interface List Entry for more information )
            x - This field repeats 10 times for each prefered interface list entry
        
            Format of Preferred Interface List Entry

            Offset 	Type 	Field
            Dec 	Hex
            0 	0 	CHAR(15) 	Preferred interface Internet address
            15 	F 	CHAR(1) 	Reserved
            16 	10 	BINARY(4) 	Preferred interface Internet address binary
            20 	14 	CHAR(*) 	Reserved

        */
        AS400DataType[] netifacDataTypeV5R3 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(15),
            new AS400Text(3),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(24),
            new AS400Text(24)
        };

        AS400DataType[] netifacDataTypeV5R4 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(15),
            new AS400Text(3),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(24),
            new AS400Text(24),
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            //Subtable : 10 entries:
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4()                        
        };

        
        AS400DataType[] netifacDataTypeV6R1 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(15),
            new AS400Text(3),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(24),
            new AS400Text(24),
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin8(),            
            new AS400Text(8),
            new AS400Text(6),
            //Subtable : 10 entries:
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4()                        
        };

        AS400DataType[] netifacDataTypeV7R1 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(15),
            new AS400Text(3),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(24),
            new AS400Text(24),
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin8(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Bin8(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(1),            
            //Subtable : 10 entries:
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4()                        
        };

        AS400DataType[] netifacDataTypeV7R2 = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(10),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Text(15),
            new AS400Text(3),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(24),
            new AS400Text(24),
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Text(50),
            new AS400Text(2),
            new AS400Bin4(),            
            new AS400Bin4(),            
            new AS400Bin8(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Bin8(),            
            new AS400Text(8),
            new AS400Text(6),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Bin4(),            
            //Subtable : 10 entries:
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4()                        
        };
        
        
        AS400DataType[] netifacSubDataType = new AS400DataType[]{
            new AS400Text(15),
            new AS400Text(1),
            new AS400Bin4(),            
            //reserved dynamic field not included
        };
        
        if ((secure ? secureConnection : insecureConnection).getVRM() <= 0x00050300)
           return retrieveUserSpace("NETIFAC", curLib, netifacDataTypeV5R3);
        if ((secure ? secureConnection : insecureConnection).getVRM() == 0x00050400)
           return retrieveUserSpace("NETIFAC", curLib, netifacDataTypeV5R4);
        else if ((secure ? secureConnection : insecureConnection).getVRM() == 0x00060100)
           return retrieveUserSpace("NETIFAC", curLib, netifacDataTypeV6R1);
        else if ((secure ? secureConnection : insecureConnection).getVRM() == 0x00070100)
           return retrieveUserSpace("NETIFAC", curLib, netifacDataTypeV7R1);
        else if ((secure ? secureConnection : insecureConnection).getVRM() >= 0x00070200)
           return retrieveUserSpace("NETIFAC", curLib, netifacDataTypeV7R2);
        else return null;       
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
        
        
        String userSpaceName = IBMiUtilities.padTrimString(uspcName.toUpperCase(), 10);
                
        String userSpaceLib = IBMiUtilities.padTrimString(uspcLibrary.toUpperCase(), 10);
                
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(quscusat.getMessageList()));
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
        
        
        String userSpaceName = IBMiUtilities.padTrimString(uspcName.toUpperCase(), 10);
                
        String userSpaceLib = IBMiUtilities.padTrimString(uspcLibrary.toUpperCase(), 10);
                
        
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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qusrusat.getMessageList()));
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
        return (int)(returnedArray[2]);
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
        
        return retrieveUserSpace(uspcName, uspcLibrary, fieldFormat, 0, "");
        
    }

    public String retrieveUserSpace(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat, String databaseName)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        return retrieveUserSpace(uspcName, uspcLibrary, fieldFormat, 0, "");
        
    }    
    
    public String retrieveUserSpace(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat, int skipHeaderBytes)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        return retrieveUserSpace(uspcName, uspcLibrary, fieldFormat, skipHeaderBytes, "");        
    }
    
    public Object[] getUserSpaceHeaderData(String uspcName, String uspcLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        ProgramCall qusrtvus = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qusrtvusParms = new ProgramParameter[4]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char20Converter = new AS400Text(20);        

        String userSpaceName = IBMiUtilities.padTrimString(uspcName.toUpperCase(), 10);

        String userSpaceLib = IBMiUtilities.padTrimString(uspcLibrary.toUpperCase(), 10);


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
            Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qusrtvus.getMessageList()));
            return null;
            }

        //https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/apiref/usfgeneral.htm
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

    public String retrieveUserSpaceFile(String uspcName, String uspcLibrary)
            throws PropertyVetoException, AS400SecurityException, 
                   ErrorCompletingRequestException, IOException, 
                   InterruptedException, ObjectDoesNotExistException, SQLException {
        
        int userSpaceLength = getUserSpaceLength(uspcName, uspcLibrary);
        
        if ((insecureConnection==null && secureConnection==null) || userSpaceLength <=0 )
            return null;
        
        Object[] offsetData = getUserSpaceHeaderData(uspcName, uspcLibrary);
        int dataOffset = (int)offsetData[0];
        
        ProgramCall qusrtvus = new ProgramCall(secure ? secureConnection : insecureConnection);        
        ProgramParameter[] qusrtvusParms = new ProgramParameter[4]; //only mandatory params at the moment

        AS400Bin4 bin4 = new AS400Bin4();      
        AS400Text char20Converter = new AS400Text(20);        

        String userSpaceName = IBMiUtilities.padTrimString(uspcName.toUpperCase(), 10);
        String userSpaceLib = IBMiUtilities.padTrimString(uspcLibrary.toUpperCase(), 10);
        
        int curOffset = 0;
        
        File jarFile = new File(IBMiConnector.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        String jarPath = jarFile.getParentFile().getPath();
        String userSpaceTempFileName = jarPath + File.separator + uspcLibrary + "_" + uspcName + "_" + new SimpleDateFormat("YYMMddHHmmSS").format(new java.util.Date());

        IBMiUtilities.prepareFile(userSpaceTempFileName);
        FileOutputStream fileOutStream = new FileOutputStream(userSpaceTempFileName);
        
        while (curOffset <= userSpaceLength) {
            qusrtvusParms[0] = new ProgramParameter(char20Converter.toBytes(userSpaceName + userSpaceLib));
            qusrtvusParms[0].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvusParms[1] = new ProgramParameter(bin4.toBytes(curOffset + 1 + dataOffset));           
            qusrtvusParms[1].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            int bufferSize = (userSpaceLength - (curOffset - 1) > DEFAULT_USERSPACE_READ_BUFFER_SIZE ? 
                    DEFAULT_USERSPACE_READ_BUFFER_SIZE : (int)(userSpaceLength - (curOffset - 1)));
            qusrtvusParms[2] = new ProgramParameter(bin4.toBytes(bufferSize));           
            qusrtvusParms[2].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvusParms[3] = new ProgramParameter(bufferSize);           
            qusrtvusParms[3].setParameterType(ProgramParameter.PASS_BY_REFERENCE);
            qusrtvus.setProgram("/qsys.lib/qusrtvus.pgm", qusrtvusParms);
            if (!qusrtvus.run()) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qusrtvus.getMessageList()));
                return null;
            }
            fileOutStream.write(qusrtvusParms[3].getOutputData());
            curOffset += DEFAULT_USERSPACE_READ_BUFFER_SIZE;
        }
        fileOutStream.close();

        return userSpaceTempFileName;
    }

    public String retrieveUserSpace(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat, int skipHeaderBytes, String databaseName)
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
        String userSpaceTempFileName = retrieveUserSpaceFile(uspcName, uspcLibrary);

        int fieldLength = IBMiUtilities.sumDataTypeFields(fieldFormat);
        
        if ((insecureConnection==null && secureConnection==null) || 
             fieldLength == 0 || userSpaceTempFileName == null )
            return dbUserSpaceName;

        FileInputStream fileInStream = new FileInputStream(userSpaceTempFileName);        
        dbUserSpaceName = (databaseName == "" ? 
                                dbTempConnection.createTempTable(uspcName+uspcLibrary, fieldFormat.length)
                                : databaseName);
        
        byte[] readBuffer = new byte[fieldLength];
        
        while (fileInStream.read(readBuffer) != -1) {            
            AS400Structure returnedDataConverter = new AS400Structure(fieldFormat);
            Object[] returnedArray = (Object[]) returnedDataConverter.toObject(readBuffer, 0);
            if (returnedArray.length != fieldFormat.length) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Received data format does not match.");
                return null;
            }
            
            Vector arrayData = new Vector();
            
            for (Object arrayElement : returnedArray)
                arrayData.addElement(arrayElement.toString().trim());
            
            dbTempConnection.insertrow(dbUserSpaceName, arrayData);
        }
        
        return dbUserSpaceName;
    }
    
    public String retrieveUserSpace2(String uspcName, String uspcLibrary, AS400DataType[] fieldFormat, int skipHeaderBytes)
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
        
        long userSpaceLength = getUserSpaceLength(uspcName, uspcLibrary);
        int fieldLength = IBMiUtilities.sumDataTypeFields(fieldFormat);
        
        if ((insecureConnection==null && secureConnection==null) || 
             fieldLength == 0 || userSpaceLength <=0 || userSpaceLength < fieldLength )
            return dbUserSpaceName;

        dbUserSpaceName = dbTempConnection.createTempTable(uspcName+uspcLibrary, fieldFormat.length);
        
        Object[] offsetData = getUserSpaceHeaderData(uspcName, uspcLibrary);
        int dataOffset = (Integer)offsetData[0];
        int maxRecords = (int)((userSpaceLength - dataOffset) / fieldLength);
        for (int curRecord=0; curRecord<maxRecords; curRecord++) {
            ProgramCall qusrtvus = new ProgramCall(secure ? secureConnection : insecureConnection);        
            ProgramParameter[] qusrtvusParms = new ProgramParameter[4]; //only mandatory params at the moment

            AS400Bin4 bin4 = new AS400Bin4();      
            AS400Text char20Converter = new AS400Text(20);        

            String userSpaceName = IBMiUtilities.padTrimString(uspcName.toUpperCase(), 10);

            String userSpaceLib = IBMiUtilities.padTrimString(uspcLibrary.toUpperCase(), 10);

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
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, IBMiUtilities.stringFromAS400Message(qusrtvus.getMessageList()));
                return null;
            }
            
            AS400Structure returnedDataConverter = new AS400Structure(fieldFormat);
            Object[] returnedArray = (Object[]) returnedDataConverter.toObject(qusrtvusParms[3].getOutputData(), 0);
            if (returnedArray.length != fieldFormat.length) {
                Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, "Received data format does not match.");
                return null;
            }
            
            Vector arrayData = new Vector();
            
            for (Object arrayElement : returnedArray)
                arrayData.addElement(arrayElement.toString().trim());
            
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
            
            createUserSpace("ALLPTFS", curLib, "ALLPTFS", 1, "PTF user space");
            if (!makeUserSpaceAutoExtendible("ALLPTFS", curLib, true))
                return dbPTFName;

            String userSpaceName = IBMiUtilities.padTrimString("ALLPTFS   " + curLib.toUpperCase(), 20);
            
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
                String productDescription = IBMiUtilities.padTrimString(product.getProductID(), 7) +
                                            IBMiUtilities.padTrimString("*ALL", 6) +
                                            IBMiUtilities.padTrimString("*ALL", 4) +
                                            IBMiUtilities.padTrimString("*ALL", 10) +
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
                            Logger.getLogger(IBMiConnector.class.getName()).log(Level.INFO, IBMiUtilities.stringFromAS400Message(qpzlstfx.getMessageList()));
                            return null;
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
        else return null;
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

        if (createUserSpace("RSTFUSRSPC", "QTEMP", " ", 1, "") == false) {
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
        userSpaceContent.write(char10Converter.toBytes(IBMiUtilities.padTextRight(restoreLibrary, 10)));
        userSpaceContent.write(bin4.toBytes(new Integer(26)));
        userSpaceContent.write(bin4.toBytes(new Integer(3)));
        userSpaceContent.write(bin4.toBytes(new Integer(14)));
        userSpaceContent.write(bin4.toBytes(new Integer(1)));
        userSpaceContent.write(char10Converter.toBytes("*SAVF     "));
        userSpaceContent.write(bin4.toBytes(new Integer(32)));
        userSpaceContent.write(bin4.toBytes(new Integer(4)));
        userSpaceContent.write(bin4.toBytes(new Integer(20)));
        userSpaceContent.write(char10Converter.toBytes(IBMiUtilities.padTextRight(savfName, 10)));
        userSpaceContent.write(char10Converter.toBytes(IBMiUtilities.padTextRight(savfLibrary, 10)));
        
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
    
    public DefaultTableModel queryResultsTable(String queryString, String[] filterParam) 
            throws SQLException {
        return dbTempConnection.query(queryString, filterParam).toTableModel();
    }

    public DefaultTableModel queryResultsTable(String queryString) 
            throws SQLException {
        return dbTempConnection.query(queryString).toTableModel();
    }
    
    /////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////
    // PRIVATE METHODS
    /////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////

    private String composeDESHashFromTokens(String PW_TOKENa, String PW_TOKENb){
        //This method is valid only for passwords longer than 8 chars (see RFC2877, 5.2).
        if (PW_TOKENb.equals("4040404040404040"))
            return PW_TOKENa;

        long l_a = Long.parseLong(PW_TOKENa, 16); //with JDK1.8,use parseUnsignedLong
        long l_b = Long.parseLong(PW_TOKENb, 16); //with JDK1.8,use parseUnsignedLong
        long l_pwtoken = l_a ^ l_b;
        return String.format("%016x", l_pwtoken).toUpperCase();
    }
    
    private String getLastPrintJobNumber() 
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
    
    private int getLastPrintNumber(String spoolName) 
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
       
    private UserList getAllUserObjects() 
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

        public IFSFileListModel(String root, final String filter){ 
            this.root = new IFSJavaFile(secure ? secureConnection : insecureConnection, root); 
            
            class hack400IFSFileFilter implements IFSFileFilter {

                @Override
                public boolean accept(IFSFile ifsf) {
                    return ifsf.getName().toUpperCase().endsWith(filter);
                }
                
            } 
            /*
            IFSFileFilter = (File dir, String name) -> {
                String uppercaseName = name.toUpperCase();
                return uppercaseName.endsWith(filter);
            }; */          
            
            fileList = this.root.list(new hack400IFSFileFilter());
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
        
        class IBMiIFSDirectoryFilter implements IFSFileFilter {
            @Override
            public boolean accept(IFSFile ifsf) {
                try {
                    return ifsf.isDirectory();
                } catch (IOException ex) {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
                    return false;
                }
            }                
        } 
        
        protected IBMiIFSDirectoryFilter IFSDirectoryFilter;

        public IFSFileTreeModel(String root){ 
            this.root = new IFSJavaFile(secure ? secureConnection : insecureConnection, root); 
    /*        IFSDirectoryFilter = (IFSFile ifsf) -> {
                try {
                    return ifsf.isDirectory();
                } catch (IOException ex) {
                    Logger.getLogger(IBMiConnector.class.getName()).log(Level.SEVERE, null, ex);
                    return false;
                }
            };*/
            IFSDirectoryFilter = new IBMiIFSDirectoryFilter();
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