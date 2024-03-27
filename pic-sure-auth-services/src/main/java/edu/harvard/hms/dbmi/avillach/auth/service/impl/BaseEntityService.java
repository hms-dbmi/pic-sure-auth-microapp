package edu.harvard.hms.dbmi.avillach.auth.service.impl;

import edu.harvard.dbmi.avillach.data.entity.BaseEntity;
import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.validation.constraints.NotNull;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * <p>Template for basic operations for REST entity classes.</p>
 * @param <T>
 */
public abstract class BaseEntityService<T extends BaseEntity> {

    private final Logger logger;

    protected final Class<T> type;

    private final String auditLogName;


    protected BaseEntityService(Class<T> type){
        this.type = type;
        auditLogName = type.getSimpleName().equals(User.class.getSimpleName()) ? "ADMIN_LOG" : "SUPER_ADMIN_LOG";
        logger = LoggerFactory.getLogger(type);
    }

    public ResponseEntity<?> getEntityById(String id, BaseRepository baseRepository){
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String principalName = securityContext.getAuthentication().getName();
        logger.info("User: " + principalName
                + " Looking for " + type.getSimpleName() +
                " by ID: " + id + "...");

        T t = (T) baseRepository.getById(UUID.fromString(id));

        if (t == null)
            return PICSUREResponse.protocolError(type.getSimpleName() + " is not found by given " +
                    type.getSimpleName().toLowerCase() + " ID: " + id);
        else
            return PICSUREResponse.success(t);
    }

    public ResponseEntity<?> getEntityAll(BaseRepository baseRepository){
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String principalName = securityContext.getAuthentication().getName();
        logger.info("User: " + principalName +
                " Getting all " + type.getSimpleName() +
                "s...");
        List<T> ts = null;

        ts = baseRepository.list();

        if (ts == null)
            return PICSUREResponse.applicationError("Error occurs when listing all "
                    + type.getSimpleName() +
                    "s.");

        return PICSUREResponse.success(ts);
    }

    public ResponseEntity<?> addEntity(List<T> entities, BaseRepository baseRepository){
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String username = securityContext.getAuthentication().getName();
		if (entities == null  ||  entities.isEmpty())
            return PICSUREResponse.protocolError("No " + type.getSimpleName().toLowerCase() +
                    " to be added.");

        logger.info("User: " + username + " is trying to add a list of "
                + type.getSimpleName());

        List<T> addedEntities = addOrUpdate(entities, true, baseRepository);
        for(T entity : addedEntities) {
			logger.info(auditLogName + " ___ " + username + " ___ created ___ "+ entity.toString() + " ___ ");
		}
   
        if (addedEntities.isEmpty())
            return PICSUREResponse.protocolError("No " + type.getSimpleName().toLowerCase() +
                    "(s) has been added.");

        if (addedEntities.size() < entities.size())
            return PICSUREResponse.success(Integer.toString(entities.size()-addedEntities.size())
                    + " " + type.getSimpleName().toLowerCase() +
                    "s are NOT operated." +
                    " Added " + type.getSimpleName().toLowerCase() +
                    "s are as follow: ", addedEntities);

        return PICSUREResponse.success("All " + type.getSimpleName().toLowerCase() +
                "s are added.", addedEntities);
    }

    public ResponseEntity<?> updateEntity(List<T> entities, BaseRepository baseRepository){
        if (entities == null  ||  entities.isEmpty())
            return PICSUREResponse.protocolError("No " + type.getSimpleName().toLowerCase() +
                    " to be updated.");

        SecurityContext securityContext = SecurityContextHolder.getContext();
        String username = securityContext.getAuthentication().getName();
		logger.info("User: " + username + " is trying to update a list of "
                + type.getSimpleName());

        List<T> addedEntities = addOrUpdate(entities, false, baseRepository);

        if (addedEntities.isEmpty())
            return PICSUREResponse.protocolError("No " + type.getSimpleName().toLowerCase() +
                    "(s) has been updated.");

        for(T entity : addedEntities) {
			logger.info(auditLogName + " ___ " + username + " ___ updated ___ "+ entity.toString() + " ___ ");
		}

        if (addedEntities.size() < entities.size())
            return PICSUREResponse.success(Integer.toString(entities.size()-addedEntities.size())
                    + " " +type.getSimpleName().toLowerCase()+
                    "s are NOT operated." +
                    " Updated " + type.getSimpleName().toLowerCase() +
                    "(s) are as follow: ", addedEntities);

        return PICSUREResponse.success("All " + type.getSimpleName().toLowerCase() +
                "(s) are updated.", addedEntities);

    }

    protected List<T> addOrUpdate(@NotNull List<T> entities, boolean forAdd, BaseRepository baseRepository){
        List<T> operatedEntities = new ArrayList<>();
        for (T t : entities){
            boolean dbContacted = false;
            if (forAdd) {
                t.setUuid(null);
                baseRepository.persist(t);
                dbContacted = true;
            }
            else {
                if (updateAllAttributes(t, baseRepository)){
                    dbContacted = true;
                }
            }

            if (!dbContacted  ||  t.getUuid() == null  ||  baseRepository.getById(t.getUuid()) == null){
                continue;
            }

            t = (T) baseRepository.getById(t.getUuid());
            operatedEntities.add(t);
        }
        return operatedEntities;
    }

    private boolean updateAllAttributes(T detachedT, BaseRepository<T, UUID> baseRepository){
        UUID uuid = detachedT.getUuid();
        if (uuid == null)
            return false;

        T retrievedT = baseRepository.getById(uuid);

        if (retrievedT == null)
            return false;

        try {
            for (Field field : detachedT.getClass().getDeclaredFields()){
                String fieldName = field.getName();
                fieldName = fieldName.substring(0,1).toUpperCase() + fieldName.substring(1);
                String getter = "get" + fieldName;
                Class<?> type = field.getType();
                if (type == boolean.class  ||  type == null) {
                    getter = "is" + fieldName;
                }

                String setter = "set" + fieldName;

                Object value = detachedT.getClass().getMethod(getter).invoke(detachedT);
                Object retrievedValue = retrievedT.getClass().getMethod(getter).invoke(retrievedT);

                /**
                 * so the problem trying to solve here is:
                 * There is an POST_COLLECTION_UPDATE event will be triggered when
                 * later merging the entity. Even the performance down to the sql
                 * statement is not being affected, we still need to take care here
                 */
                boolean inputCollectionMatchedDBCollection = true;
                String simpleName = type.getSimpleName();
                if (simpleName.contains("Set")  ||  simpleName.contains("List")) {

                    if (retrievedValue != null){
                        Collection<BaseEntity> retrievedCollection = (Collection<BaseEntity>)retrievedValue;
                        Collection<BaseEntity> detachedCollection = (Collection<BaseEntity>)value;

                        if (retrievedCollection != null && detachedCollection != null){
                            for (BaseEntity baseEntity : retrievedCollection) {
                                if (!detachedCollection.contains(baseEntity)) {
                                    inputCollectionMatchedDBCollection = false;
                                    break;
                                }
                            }
                            for (BaseEntity baseEntity : detachedCollection) {
                                if (!retrievedCollection.contains(baseEntity)) {
                                    inputCollectionMatchedDBCollection = false;
                                    break;
                                }
                            }
                        } else {
                            inputCollectionMatchedDBCollection = false;
                        }
                    } else {
                        inputCollectionMatchedDBCollection = false;
                    }
                } else {
                    inputCollectionMatchedDBCollection = false;
                }

                if (value != null && !inputCollectionMatchedDBCollection) {
                    detachedT.getClass().getMethod(setter, field.getType())
                            .invoke(retrievedT, value);
                }
            }
        } catch (IllegalArgumentException | ReflectiveOperationException ex /* | IntrospectionException ex */){
            ex.printStackTrace();
            return false;
        }

        baseRepository.merge(retrievedT);

        return true;
    }

    public ResponseEntity<?> removeEntityById(String id, BaseRepository baseRepository) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String username = securityContext.getAuthentication().getName();
		logger.info("User: " + username + " is trying to REMOVE an entity: "
                + type.getSimpleName() + ", by uuid: " + id);

        UUID uuid = UUID.fromString(id);
        T t = (T) baseRepository.getById(uuid);
        if (t == null)
            return PICSUREResponse.protocolError(type.getSimpleName() +
                    " is not found by " + type.getSimpleName().toLowerCase() +
                    " ID");

        baseRepository.remove(t);
		logger.info(auditLogName + " ___ " + username + " ___ updated ___ "+ t.toString() + " ___ ");

        
        t = (T) baseRepository.getById(uuid);
        if (t != null){
            return PICSUREResponse.applicationError("Cannot delete the " + type.getSimpleName().toLowerCase()+
                    " by id: " + id);
        }

        return PICSUREResponse.success("Successfully deleted " + type.getSimpleName().toLowerCase() +
                        " by id: " + id + ", listing rest of the " + type.getSimpleName().toLowerCase() +
                        "(s) as below"
                , baseRepository.list());

    }
}
