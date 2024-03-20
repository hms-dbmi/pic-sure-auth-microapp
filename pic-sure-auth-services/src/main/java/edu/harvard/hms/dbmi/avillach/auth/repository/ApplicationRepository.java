package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * <p>Provides operations for the Application entity to interact with a database.</p>>
 *
 * @see Application
 */

// TODO: A repository class is not the right place to annotate with transactional. Verify?
// TODO: Is there a reason why we would scope this to the application?
@Repository
public class ApplicationRepository extends BaseRepository<Application, UUID> {

    protected ApplicationRepository() {
        super(Application.class);
    }
}
