package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.UserMetadataMapping;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * <p>Provides operations for the UserMetadataMapping entity to interact with a database.</p>
 * @see UserMetadataMapping
 */

@Repository
public class UserMetadataMappingRepository extends BaseRepository<UserMetadataMapping, UUID> {

	protected UserMetadataMappingRepository() {
		super(UserMetadataMapping.class);
	}

	public List<UserMetadataMapping> findByConnection(Connection connection) {
		return getByColumn("connection", connection);
	}
	
}
