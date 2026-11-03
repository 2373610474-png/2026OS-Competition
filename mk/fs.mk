########################################################
# DISK IMAGE
########################################################

DISK_IMG := ./disk.img
DISK_IMG_COPY := ./disk-copy.img
TEST_CASE_DIR := ./testcase
disk-img: user
	$(call building, "building $(DISK_IMG) for online judge")

	$(call building, "cleaning up")
	rm -f $(DISK_IMG)

	$(call building, extracting testcase)
	chmod +x scripts/archive.sh
	./scripts/archive.sh extract

	$(call building, extracting vendor)
	chmod +x scripts/archive2.sh
	./scripts/archive2.sh extract

	$(call building, "making disk-img dir")
	mkdir -p mnt
	dd if=/dev/zero of=$(DISK_IMG) bs=1M count=4096
	mkfs.ext4 -F -O ^metadata_csum_seed $(DISK_IMG)
	mount $(DISK_IMG) mnt

	$(call building, "start to copy tests from $(TEST_CASE_DIR)")
	cp -r $(TEST_CASE_DIR)/* mnt/

	$(call building, "copying user apps and tests to the $(DISK_IMG)")
	cp -r $(USER_ELFS_RV) mnt/riscv
	cp -r $(USER_ELFS_LA) mnt/loongarch

	$(call building, "copying auto test scripts")
	cp ./scripts/run-rv-oj.sh mnt/riscv/run-oj.sh
	cp ./scripts/run-la-oj.sh mnt/loongarch/run-oj.sh
	cp ./scripts/run-ltp-rv.sh mnt/riscv/run-ltp-rv.sh
	cp ./scripts/run-ltp-la.sh mnt/loongarch/run-ltp-la.sh

	$(call building, "create bin/ lib/ dir")
	mkdir mnt/bin
	mkdir mnt/lib
	mkdir mnt/lib64
	mkdir mnt/usr
	mkdir mnt/usr/lib64

	cp -r attach mnt/

	umount mnt
	rm -rf mnt
	chmod 777 $(DISK_IMG)
	$(call success, "building $(DISK_IMG) finished")
	cp $(DISK_IMG) $(DISK_IMG_COPY)
	$(call success, "cp $(DISK_IMG) to $(DISK_IMG_COPY) finished")

.PHONY: disk-img
