// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.protocol.db;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.String;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.message.Message;
import org.fidoalliance.fdo.protocol.Config;
import org.fidoalliance.fdo.protocol.InternalServerErrorException;
import org.fidoalliance.fdo.protocol.LoggerService;
import org.fidoalliance.fdo.protocol.Mapper;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoModule;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoSendFunction;
import org.fidoalliance.fdo.protocol.entity.SystemPackage;
import org.fidoalliance.fdo.protocol.entity.SystemResource;
import org.fidoalliance.fdo.protocol.message.AnyType;
import org.fidoalliance.fdo.protocol.message.DevModList;
import org.fidoalliance.fdo.protocol.message.EotResult;
import org.fidoalliance.fdo.protocol.message.ServiceInfoKeyValuePair;
import org.fidoalliance.fdo.protocol.message.ServiceInfoModuleState;
import org.fidoalliance.fdo.protocol.message.ServiceInfoQueue;
import org.fidoalliance.fdo.protocol.message.StatusCb;
import org.fidoalliance.fdo.protocol.serviceinfo.DevMod;
import org.fidoalliance.fdo.protocol.serviceinfo.FdoSys;
import org.h2.util.json.JSONObject;
import org.hibernate.Session;
import org.hibernate.Transaction;

/**
 * Implements FdoSysModule spec.
 */
public class FdoSysOwnerModule implements ServiceInfoModule {

  private String serialnumber;
  private Map<String, String> serialNumbers = new HashMap<>();
  //private ThreadLocal<String> serialnumber = new ThreadLocal<>();
  private String guid;  
  private String ST;
  private String securityToken;
  private String updateStatus;
  private String retrivedStatus = "registered" ;
  private String hawkbitserver= "host.docker.internal";

  private final LoggerService logger = new LoggerService(FdoSysOwnerModule.class);
 
  @Override
  public String getName() {
    return FdoSys.NAME;
  }

  @Override
  public void prepare(ServiceInfoModuleState state) throws IOException {
    state.setExtra(AnyType.fromObject(new FdoSysModuleExtra()));
  }

  @Override
  public void receive(ServiceInfoModuleState state, ServiceInfoKeyValuePair kvPair)
      throws IOException {
    FdoSysModuleExtra extra = state.getExtra().covertValue(FdoSysModuleExtra.class);
    switch (kvPair.getKey()) {
      case DevMod.KEY_MODULES: {
        DevModList list =
            Mapper.INSTANCE.readValue(kvPair.getValue(), DevModList.class);
        for (String name : list.getModulesNames()) {
          if (name.equals(FdoSys.NAME)) {
            state.setActive(true);
            ServiceInfoQueue queue = extra.getQueue();
            ServiceInfoKeyValuePair activePair = new ServiceInfoKeyValuePair();
            activePair.setKeyName(FdoSys.ACTIVE);
            activePair.setValue(Mapper.INSTANCE.writeValue(true));
            queue.add(activePair);
          }
        }
      }
      break;
      case DevMod.KEY_DEVICE:
      case DevMod.KEY_OS:
      case DevMod.KEY_VERSION:
      case DevMod.KEY_ARCH:
        extra.getFilter().put(kvPair.getKey(),
            Mapper.INSTANCE.readValue(kvPair.getValue(), String.class));
        break;
      case DevMod.KEY_SN:
        guid = state.getGuid().toString();
        serialnumber =  Mapper.INSTANCE.readValue(kvPair.getValue(), String.class);
        serialNumbers.put(guid, serialnumber);
        break;
      case FdoSys.STATUS_CB:
        if (state.isActive()) {
          StatusCb status = Mapper.INSTANCE.readValue(kvPair.getValue(), StatusCb.class);

          //send notification of status
          ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
          kv.setKeyName(FdoSys.STATUS_CB);
          kv.setValue(Mapper.INSTANCE.writeValue(status));
          extra.getQueue().add(kv);
          onStatusCb(state, extra, status);
          if (status.isCompleted()) {
            // check for error
            if (status.getRetCode() != 0) {
              throw new InternalServerErrorException("Exec_cb status returned failure.");
            }
            extra.setWaiting(false);
            extra.getQueue().addAll(extra.getWaitQueue());
            extra.setWaitQueue(new ServiceInfoQueue());
          }
        }
        break;
      case FdoSys.DATA:
        if (state.isActive()) {
          byte[] data = Mapper.INSTANCE.readValue(kvPair.getValue(), byte[].class);
          onFetch(state, extra, data);
        }
        break;
      case FdoSys.EOT:
        if (state.isActive()) {
          extra.setWaiting(false);
          extra.setQueue(extra.getWaitQueue());
          extra.setWaitQueue(new ServiceInfoQueue());
          EotResult result = Mapper.INSTANCE.readValue(kvPair.getValue(), EotResult.class);
          onEot(state, extra, result);
        }
        break;
      default:
        break;
    }
    state.setExtra(AnyType.fromObject(extra));
  }
  
  /* Function to send the data to the linux client */
  @Override
  public void send(ServiceInfoModuleState state, ServiceInfoSendFunction sendFunction)
      throws IOException {
     /*Check the filters and Que for other service modules to be executed */
    FdoSysModuleExtra extra = state.getExtra().covertValue(FdoSysModuleExtra.class);
    
    guid = state.getGuid().toString();
    serialnumber = serialNumbers.get(guid);
    securityToken = createHawkbitTarget(state,guid);

    
      createHawkbitConfig(extra);
      writeHawkbitConfig(state,extra,securityToken,guid);
      //wait for device to get registered
      try {
        Thread.sleep(5000);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }    

    while (extra.getQueue().size() > 0) {
      boolean sent = sendFunction.apply(extra.getQueue().peek());
      if (sent) {
        checkWaiting(extra, extra.getQueue().poll());
      } else {
        break;
      }
      if (extra.isWaiting()) {
        break;
      }
    }
    if (extra.getQueue().size() == 0 && !extra.isWaiting()) {
      updateStatus = confirmTargetRegistration(state, guid);
      if (!updateStatus.equals(retrivedStatus)){
        state.setDone(false);
      }
      else{
        state.setDone(true);
      }
    }
    state.setExtra(AnyType.fromObject(extra));
  }

  /*create hawkbit target device and get security token */
  protected String createHawkbitTarget(ServiceInfoModuleState state, String guid) throws IOException{
    try {
      //If you've set the HISTCONTROL environment variable to ignoreboth (which is usually set by default), commands with a leading space character will not be stored in the history (as well as duplicates).
      ProcessBuilder processBuilder = new ProcessBuilder();
      processBuilder.command("bash", "-c", "HISTCONTROL=ignoreboth; " +
              "curl -k -u admin:admin \"https://" + hawkbitserver + "/rest/v1/targets\" -X POST -H \"Content-Type: application/json;charset=UTF-8\" -d '[{\"controllerId\":\"" + guid + "\",\"name\":\"" + serialnumber + "\",\"description\":\"Linutronix FDO_device\"}]' < /dev/null; " +
              "get_securityToken=$(curl -k -u admin:admin \"https://" + hawkbitserver + "/rest/v1/targets/\"" + guid + "\"\" -X GET | jq '.securityToken'); " +
              "ST=$(echo \"$get_securityToken\" | tr -d '\"'); " +
              "echo $ST" );
      processBuilder.redirectErrorStream(true);
      Process process = processBuilder.start();

      // read the output from the command
      InputStream inputStream = process.getInputStream();
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      String line;
      while ((line = reader.readLine()) != null) {
          ST = line; // reads the value of security Token
          System.out.println(line);
      }
  } catch (Exception e) {
      e.printStackTrace();
  }
    return ST;
}

/*crete hawkbit.config file */
protected void createHawkbitConfig(FdoSysModuleExtra extra) throws IOException {
  ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
  kv.setKeyName(FdoSys.FILEDESC);
  String filename = "hawkbit.config";
  kv.setValue(Mapper.INSTANCE.writeValue(filename));
  extra.getQueue().add(kv);
}

/*write hawkbit.config file */
protected void writeHawkbitConfig(ServiceInfoModuleState state,FdoSysModuleExtra extra, String securityToken, String guid ) throws IOException {
  guid = state.getGuid().toString();
  String CFG = "URL:https://"+ hawkbitserver +"\n"
  + "ControllerId:"+ guid +" \n"
  + "SecurityToken:"+ securityToken +"\n";

    InputStream targetStream = new ByteArrayInputStream(CFG.getBytes());
      try (InputStream input = targetStream) {
        for (; ; ) {
          byte[] data = new byte[state.getMtu() - 26];
          int br = input.read(data);
          if (br == -1) {
            break;
          }
          ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
          kv.setKeyName(FdoSys.WRITE);

          if (br < data.length) {
            byte[] temp = data;
            data = new byte[br];
            System.arraycopy(temp, 0, data, 0, br);
          }
          kv.setValue(Mapper.INSTANCE.writeValue(data));
          extra.getQueue().add(kv);
        }
      } 
  }


protected String confirmTargetRegistration(ServiceInfoModuleState state, String guid) throws IOException{
  try {
    //If you've set the HISTCONTROL environment variable to ignoreboth (which is usually set by default), commands with a leading space character will not be stored in the history (as well as duplicates).
    guid = state.getGuid().toString();
    ProcessBuilder processBuilder = new ProcessBuilder();
    processBuilder.command("bash", "-c", "HISTCONTROL=ignoreboth; " +
            "get_updateStatus=$(curl -k -u admin:admin \"https://" + hawkbitserver + "/rest/v1/targets/\"" + guid + "\"\" -X GET | jq '.updateStatus'); " +
            "updateStatus=$(echo \"$get_updateStatus\" | tr -d '\"'); " +
            "echo $updateStatus" );
    processBuilder.redirectErrorStream(true);
    Process process = processBuilder.start();

    // read the output from the command
    InputStream inputStream = process.getInputStream();
    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
    String line;
    while ((line = reader.readLine()) != null) {
        updateStatus = line; // reads the value of updateStatus
        System.out.println(line);
    }
    
} catch (Exception e) {
    e.printStackTrace();
}
return updateStatus;
}
  protected void checkWaiting(FdoSysModuleExtra extra, ServiceInfoKeyValuePair kv) {
    switch (kv.getKey()) {
      case FdoSys.EXEC_CB:
      case FdoSys.FETCH:
        extra.setWaiting(true);
        extra.setWaitQueue(extra.getQueue());
        extra.setQueue(new ServiceInfoQueue());
        break;
      default:
        break;
    }
  }

  protected void onStatusCb(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      StatusCb status) throws IOException {
    logger.info("status_cb completed " + status.isCompleted() + " retcode "
        + status.getRetCode() + " timeout " + status.getTimeout());
  }

  protected void onFetch(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      byte[] data) throws IOException {

    logger.warn(new String(data, StandardCharsets.US_ASCII));
  }

  protected void onEot(ServiceInfoModuleState state, FdoSysModuleExtra extra, EotResult result)
      throws IOException {
    logger.info("EOT:resultCode " + result.getResult());
  }

  protected void getExec(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.EXEC);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getExecArgs()));
    extra.getQueue().add(kv);
  }

  protected void getExecCb(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.EXEC_CB);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getExecCbArgs()));
    extra.getQueue().add(kv);
  }

  protected void getFetch(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.FETCH);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getFetch()));
    extra.getQueue().add(kv);
  }
}


