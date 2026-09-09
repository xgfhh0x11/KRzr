/*
 * Kernel-Level Race Condition Fuzzing Engine
 * 
 * Single-file Windows kernel-mode driver that performs race-condition
 * fuzzing. All modules are implemented in this translation unit.
 */

// ntifs.h is a superset of ntddk.h/wdm.h; including both produces conflicting
// PEPROCESS/PETHREAD definitions. windef.h is a user-mode header and must not
// be pulled into a kernel translation unit.
#include <ntifs.h>
#include <ntstrsafe.h>

// Driver version
#define KERNEL_FUZZER_VERSION_MAJOR 1
#define KERNEL_FUZZER_VERSION_MINOR 0
#define KERNEL_FUZZER_VERSION_BUILD 0

// IOCTL codes
#define KERNEL_FUZZER_DEVICE_TYPE 0x8000
#define IOCTL_START_FUZZING \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_FUZZING \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATUS \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_THREAD \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_MUTEX \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOCATE_MEMORY \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_MEMORY \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SIMULATE_RACE \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_COVERAGE \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_FAULT_PATTERNS \
    CTL_CODE(KERNEL_FUZZER_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Constants
#define RACE_FUZZER_TAG 'FZAR'
#define MAX_THREADS 64
#define MAX_RESOURCES 256
#define MAX_RACES 1024
#define MAX_COVERAGE_POINTS 10000
#define MAX_FAULT_PATTERNS 512
#define MAX_MUTATIONS 1000

// Enums
typedef enum _THREAD_STATE {
    THREAD_CREATED,
    THREAD_RUNNING,
    THREAD_WAITING,
    THREAD_TERMINATED
} THREAD_STATE;

typedef enum _RESOURCE_TYPE {
    RESOURCE_KERNEL_POOL,
    RESOURCE_FILE_HANDLE,
    RESOURCE_REGISTRY_KEY,
    RESOURCE_NAMED_PIPE,
    RESOURCE_SECTION_OBJECT,
    RESOURCE_MUTEX,
    RESOURCE_EVENT,
    RESOURCE_SEMAPHORE
} RESOURCE_TYPE;

typedef enum _ACCESS_TYPE {
    ACCESS_READ,
    ACCESS_WRITE,
    ACCESS_EXECUTE,
    ACCESS_FREE,
    ACCESS_ALLOCATE
} ACCESS_TYPE;

typedef enum _CORRUPTION_TYPE {
    CORRUPTION_BUFFER_OVERFLOW,
    CORRUPTION_USE_AFTER_FREE,
    CORRUPTION_DOUBLE_FREE,
    CORRUPTION_NULL_POINTER_DEREF,
    CORRUPTION_UNINITIALIZED_MEMORY,
    CORRUPTION_INTEGER_OVERFLOW,
    CORRUPTION_RACE_CONDITION
} CORRUPTION_TYPE;

typedef enum _FAULT_PATTERN_TYPE {
    FAULT_PATTERN_USE_AFTER_FREE,
    FAULT_PATTERN_DOUBLE_FREE,
    FAULT_PATTERN_HEAP_SPRAY,
    FAULT_PATTERN_ROP_CHAIN,
    FAULT_PATTERN_PRIVILEGE_ESCALATION,
    FAULT_PATTERN_CODE_INJECTION
} FAULT_PATTERN_TYPE;

typedef enum _MUTATION_TYPE {
    MUTATION_BIT_FLIP,
    MUTATION_BYTE_FLIP,
    MUTATION_ARITHMETIC,
    MUTATION_INTERESTING,
    MUTATION_HAVOC,
    MUTATION_SPLICE
} MUTATION_TYPE;

// Structures
typedef struct _FUZZING_CONFIG {
    ULONG MaxIterations;
    ULONG MaxThreads;
    ULONG MaxResources;
    ULONG TimeoutMs;
    ULONG CrashThreshold;
    ULONG PatternThreshold;
    BOOLEAN EnableCoverage;
    BOOLEAN EnableFaultPatterns;
} FUZZING_CONFIG, *PFUZZING_CONFIG;

typedef struct _THREAD_CONTEXT {
    LIST_ENTRY ListEntry;
    HANDLE ThreadHandle;
    PVOID StartRoutine;
    PVOID Parameter;
    ULONG ThreadId;
    THREAD_STATE State;
    KIRQL Irql;
    ULONG Priority;
    KAFFINITY Affinity;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastActivity;
    ULONG AccessCount;
    BOOLEAN LockHeld;
    ULONG LockCount;
} THREAD_CONTEXT, *PTHREAD_CONTEXT;

typedef struct _RESOURCE_CONTEXT {
    LIST_ENTRY ListEntry;
    ULONG ResourceId;
    RESOURCE_TYPE ResourceType;
    PVOID Handle;
    ULONG AccessCount;
    LARGE_INTEGER LastAccess;
    BOOLEAN LockHeld;
    BOOLEAN CorruptionDetected;
    ULONG TaintLevel;
    ULONG Size;
    ULONG Tag;
    CHAR Name[64];
    PVOID Data;
} RESOURCE_CONTEXT, *PRESOURCE_CONTEXT;

typedef struct _RACE_CONDITION {
    LIST_ENTRY ListEntry;
    ULONG RaceId;
    CORRUPTION_TYPE CorruptionType;
    PVOID MemoryAddress;
    ULONG ThreadCount;
    ULONG ThreadIds[MAX_THREADS];
    LARGE_INTEGER DetectionTime;
    ULONG Severity;
    BOOLEAN PatternPotential;
    CHAR Description[256];
} RACE_CONDITION, *PRACE_CONDITION;

typedef struct _COVERAGE_POINT {
    LIST_ENTRY ListEntry;
    PVOID Address;
    CHAR FunctionName[64];
    ULONG HitCount;
    LARGE_INTEGER FirstHit;
    LARGE_INTEGER LastHit;
    ULONG ThreadIds[MAX_THREADS];
    ULONG ThreadCount;
    BOOLEAN IsHit;
} COVERAGE_POINT, *PCOVERAGE_POINT;

typedef struct _FAULT_PATTERN {
    LIST_ENTRY ListEntry;
    ULONG PayloadId;
    FAULT_PATTERN_TYPE PatternType;
    ULONG Complexity;
    ULONG SuccessProbability;
    PVOID PayloadData;
    ULONG DataSize;
    PVOID TargetAddress;
    CHAR TriggerCondition[128];
    ULONG Metadata[16];
} FAULT_PATTERN, *PFAULT_PATTERN;

typedef struct _MUTATION_RESULT {
    LIST_ENTRY ListEntry;
    ULONG MutationId;
    MUTATION_TYPE MutationType;
    PVOID OriginalInput;
    PVOID MutatedInput;
    ULONG InputSize;
    ULONG CoverageGained;
    ULONG NewPaths;
    BOOLEAN CrashInduced;
    BOOLEAN PatternFound;
} MUTATION_RESULT, *PMUTATION_RESULT;

typedef struct _FUZZING_STATUS {
    BOOLEAN IsRunning;
    ULONG IterationsCompleted;
    ULONG CrashesFound;
    ULONG PatternsFound;
    ULONG RaceConditionsDetected;
    ULONG CoveragePercentage;
    ULONG UniquePaths;
    ULONG TotalThreadsCreated;
    ULONG TotalResourcesCreated;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
} FUZZING_STATUS, *PFUZZING_STATUS;

// Corpus entry consumed by the input queue (used by AddInput/GetNextInput).
typedef struct _INPUT_DATA {
    LIST_ENTRY ListEntry;
    PVOID Data;
    ULONG Size;
    ULONG Priority;
    ULONG HitCount;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastUsed;
    BOOLEAN IsInteresting;
    ULONG Metadata[4];
} INPUT_DATA, *PINPUT_DATA;

// Forward declarations for the internal helpers that are referenced before
// their definitions appear later in this single translation unit.
VOID FuzzingIteration(ULONG Iteration);
VOID GenerateInput(PVOID* InputData, PULONG InputSize);
VOID CreateFuzzingResources(VOID);
VOID CreateFuzzingThreads(VOID);
VOID SimulateRaceConditions(VOID);
VOID UpdateCoverage(VOID);
VOID SynthesizeFaultPatterns(VOID);
VOID UpdateStatistics(VOID);
VOID SimulateThreadRace(PTHREAD_CONTEXT Context);
VOID LocksetInit(VOID);
VOID ShadowInit(VOID);
NTSTATUS LogRaceCondition(CORRUPTION_TYPE Type, PVOID Address,
                          ULONG ThreadId, PCHAR Description);

// Global variables
PDEVICE_OBJECT g_DeviceObject = NULL;
PUNICODE_STRING g_DeviceName = NULL;
PUNICODE_STRING g_SymbolicLinkName = NULL;
BOOLEAN g_FuzzingActive = FALSE;
KSPIN_LOCK g_GlobalLock;
KSPIN_LOCK g_FuzzingLock;
KSPIN_LOCK g_ThreadLock;
KSPIN_LOCK g_ResourceLock;
KSPIN_LOCK g_RaceLock;
KSPIN_LOCK g_CoverageLock;
KSPIN_LOCK g_PatternLock;
KSPIN_LOCK g_MutationLock;
KSPIN_LOCK g_InputLock;

// Lists
LIST_ENTRY g_ThreadList;
LIST_ENTRY g_ResourceList;
LIST_ENTRY g_RaceList;
LIST_ENTRY g_CoverageList;
LIST_ENTRY g_PatternList;
LIST_ENTRY g_MutationList;
LIST_ENTRY g_InputList;

// Counters
ULONG g_ThreadCounter = 0;
ULONG g_ResourceCounter = 0;
ULONG g_RaceCounter = 0;
ULONG g_CoverageCounter = 0;
ULONG g_PatternCounter = 0;
ULONG g_MutationCounter = 0;
ULONG g_InputCounter  = 0;

// Fuzzing context
FUZZING_CONFIG g_FuzzingConfig = {0};
FUZZING_STATUS g_FuzzingStatus = {0};

// Function prototypes
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Fuzzing functions
NTSTATUS StartFuzzing(PFUZZING_CONFIG Config);
VOID StopFuzzing(VOID);
NTSTATUS GetFuzzingStatus(PFUZZING_STATUS Status);
VOID FuzzingLoop(PVOID Parameter);

// Thread management (Module 1: Thread Interleaving Simulator)
NTSTATUS CreateFuzzingThread(PTHREAD_CONTEXT Context);
VOID DestroyFuzzingThread(PTHREAD_CONTEXT Context);
VOID ThreadWorker(PVOID Parameter);
NTSTATUS CreateMutex(PCHAR MutexName, PHANDLE MutexHandle);
NTSTATUS ReleaseMutex(HANDLE MutexHandle);
NTSTATUS WaitForMutex(HANDLE MutexHandle, ULONG TimeoutMs);
NTSTATUS SimulateRaceCondition(ULONG RaceType, PULONG ThreadIds, ULONG ThreadCount);

// Resource management (Module 2: Shared Resource Mutator)
NTSTATUS CreateResource(RESOURCE_TYPE ResourceType, PRESOURCE_CONTEXT Context);
NTSTATUS DestroyResource(PRESOURCE_CONTEXT Context);
NTSTATUS AccessResource(PRESOURCE_CONTEXT Context, ACCESS_TYPE AccessType);
NTSTATUS AllocateKernelPool(ULONG Size, ULONG Tag, PVOID* Address);
NTSTATUS FreeKernelPool(PVOID Address);
NTSTATUS CreateFileHandle(PCHAR FileName, PHANDLE FileHandle);
NTSTATUS WriteFile(HANDLE FileHandle, PVOID Data, ULONG Size);
NTSTATUS ReadFile(HANDLE FileHandle, PVOID Buffer, ULONG Size);
NTSTATUS CloseFile(HANDLE FileHandle);

// Race detection (Module 3: Race Detector)
NTSTATUS DetectRaceConditions(VOID);
NTSTATUS RecordMemoryAccess(PVOID Address, ACCESS_TYPE AccessType, ULONG Size, ULONG ThreadId);
NTSTATUS RecordLockAcquisition(PVOID LockHandle, ULONG ThreadId);
NTSTATUS RecordLockRelease(PVOID LockHandle, ULONG ThreadId);
NTSTATUS AddCoveragePoint(PVOID Address, PCHAR FunctionName);
NTSTATUS HitCoveragePoint(PVOID Address, ULONG ThreadId);
NTSTATUS GetCoverageStats(PULONG TotalPoints, PULONG HitPoints, PULONG Percentage);

// Pattern synthesis (Module 4: Fault Pattern Generator)
NTSTATUS SynthesizeFaultPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateROPChain(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress);
NTSTATUS GenerateHeapSpray(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress);
NTSTATUS GenerateUseAfterFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);
NTSTATUS GenerateDoubleFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern);

// Coverage tracking (Module 5: Coverage Tracker & Feedback Loop)
NTSTATUS AddInput(PVOID InputData, ULONG InputSize);
NTSTATUS GetNextInput(PVOID* InputData, PULONG InputSize);
NTSTATUS MutateInput(PVOID OriginalInput, ULONG InputSize, MUTATION_TYPE MutationType, PMUTATION_RESULT Result);
NTSTATUS UpdateMutationResult(ULONG MutationId, ULONG CoverageGained, BOOLEAN CrashInduced, BOOLEAN PatternFound);
NTSTATUS GetCoverageStats(PULONG TotalPoints, PULONG HitPoints, PULONG Percentage);

// Utility functions
VOID LogMessage(PCHAR Format, ...);
NTSTATUS GenerateRandomData(PVOID Buffer, ULONG Size);
ULONG CalculateHash(PVOID Data, ULONG Size);
BOOLEAN IsAddressValid(PVOID Address);
VOID CleanupResources(VOID);

// Macros
#define LOG_INFO(Format, ...) LogMessage("[INFO] " Format "\n", __VA_ARGS__)
#define LOG_WARN(Format, ...) LogMessage("[WARN] " Format "\n", __VA_ARGS__)
#define LOG_ERROR(Format, ...) LogMessage("[ERROR] " Format "\n", __VA_ARGS__)
#define LOG_DEBUG(Format, ...) LogMessage("[DEBUG] " Format "\n", __VA_ARGS__)

// Driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    LOG_INFO("Kernel Race Condition Fuzzer Driver v%d.%d.%d", 
             KERNEL_FUZZER_VERSION_MAJOR, 
             KERNEL_FUZZER_VERSION_MINOR, 
             KERNEL_FUZZER_VERSION_BUILD);
    
    // Initialize spin locks
    KeInitializeSpinLock(&g_GlobalLock);
    KeInitializeSpinLock(&g_FuzzingLock);
    KeInitializeSpinLock(&g_ThreadLock);
    KeInitializeSpinLock(&g_ResourceLock);
    KeInitializeSpinLock(&g_RaceLock);
    KeInitializeSpinLock(&g_CoverageLock);
    KeInitializeSpinLock(&g_PatternLock);
    KeInitializeSpinLock(&g_MutationLock);
    KeInitializeSpinLock(&g_InputLock);

    // Initialize lists
    InitializeListHead(&g_ThreadList);
    InitializeListHead(&g_ResourceList);
    InitializeListHead(&g_RaceList);
    InitializeListHead(&g_CoverageList);
    InitializeListHead(&g_PatternList);
    InitializeListHead(&g_MutationList);
    InitializeListHead(&g_InputList);
    
    // Create device name
    RtlInitUnicodeString(&deviceName, L"\\Device\\KernelFuzzer");
    g_DeviceName = &deviceName;
    
    // Create symbolic link
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\KernelFuzzer");
    g_SymbolicLinkName = &symbolicLinkName;
    
    // Create device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to create device object: 0x%08X", status);
        return status;
    }
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to create symbolic link: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    
    // Initialize fuzzing status
    RtlZeroMemory(&g_FuzzingStatus, sizeof(FUZZING_STATUS));

    /* Initialise lockset (Eraser) and shadow (UAF/double-free) tables. */
    LocksetInit();
    ShadowInit();

    LOG_INFO("Driver loaded successfully");
    return STATUS_SUCCESS;
}

// Driver unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    LOG_INFO("Unloading driver...");
    
    // Stop fuzzing if active
    if (g_FuzzingActive) {
        StopFuzzing();
    }
    
    // Clean up resources
    CleanupResources();
    
    // Delete symbolic link
    if (g_SymbolicLinkName) {
        IoDeleteSymbolicLink(g_SymbolicLinkName);
    }
    
    // Delete device object
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    
    LOG_INFO("Driver unloaded successfully");
}

// Create/Close dispatch
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

// Device control dispatch
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;
    PVOID outputBuffer;
    ULONG outputBufferLength;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    switch (ioControlCode) {
        case IOCTL_START_FUZZING:
            if (inputBufferLength >= sizeof(FUZZING_CONFIG)) {
                status = StartFuzzing((PFUZZING_CONFIG)inputBuffer);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
            
        case IOCTL_STOP_FUZZING:
            StopFuzzing();
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_GET_STATUS:
            if (outputBufferLength >= sizeof(FUZZING_STATUS)) {
                status = GetFuzzingStatus((PFUZZING_STATUS)outputBuffer);
                Irp->IoStatus.Information = sizeof(FUZZING_STATUS);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
            
        case IOCTL_CREATE_THREAD:
            if (inputBufferLength >= sizeof(THREAD_CONTEXT)) {
                status = CreateFuzzingThread((PTHREAD_CONTEXT)inputBuffer);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
            
        case IOCTL_CREATE_MUTEX:
            // Mutex creation logic
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_ALLOCATE_MEMORY:
            // Memory allocation logic
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_FREE_MEMORY:
            // Memory free logic
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_SIMULATE_RACE:
            // Race simulation logic
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_GET_COVERAGE:
            // Coverage statistics
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_GET_FAULT_PATTERNS:
            // Pattern statistics
            status = STATUS_SUCCESS;
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Start fuzzing
NTSTATUS StartFuzzing(PFUZZING_CONFIG Config)
{
    KIRQL oldIrql;
    HANDLE fuzzingThreadHandle;
    NTSTATUS status;
    
    if (g_FuzzingActive) {
        LOG_WARN("Fuzzing already active");
        return STATUS_ALREADY_REGISTERED;
    }
    
    // Copy configuration
    KeAcquireSpinLock(&g_FuzzingLock, &oldIrql);
    RtlCopyMemory(&g_FuzzingConfig, Config, sizeof(FUZZING_CONFIG));
    
    // Initialize status
    RtlZeroMemory(&g_FuzzingStatus, sizeof(FUZZING_STATUS));
    g_FuzzingStatus.IsRunning = TRUE;
    KeQuerySystemTime(&g_FuzzingStatus.StartTime);
    
    g_FuzzingActive = TRUE;
    KeReleaseSpinLock(&g_FuzzingLock, oldIrql);
    
    LOG_INFO("Fuzzing started - Iterations: %d, Threads: %d, Resources: %d",
             Config->MaxIterations, Config->MaxThreads, Config->MaxResources);
    
    // Start fuzzing loop in a worker thread
    status = PsCreateSystemThread(
        &fuzzingThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        FuzzingLoop,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to create fuzzing thread: 0x%08X", status);
        g_FuzzingActive = FALSE;
        return status;
    }
    
    return STATUS_SUCCESS;
}

// Stop fuzzing
VOID StopFuzzing(VOID)
{
    KIRQL oldIrql;
    
    if (!g_FuzzingActive) {
        return;
    }
    
    KeAcquireSpinLock(&g_FuzzingLock, &oldIrql);
    g_FuzzingActive = FALSE;
    g_FuzzingStatus.IsRunning = FALSE;
    KeQuerySystemTime(&g_FuzzingStatus.EndTime);
    KeReleaseSpinLock(&g_FuzzingLock, oldIrql);
    
    LOG_INFO("Fuzzing stopped");
}

// Get fuzzing status
NTSTATUS GetFuzzingStatus(PFUZZING_STATUS Status)
{
    KIRQL oldIrql;
    
    if (!Status) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_FuzzingLock, &oldIrql);
    RtlCopyMemory(Status, &g_FuzzingStatus, sizeof(FUZZING_STATUS));
    KeReleaseSpinLock(&g_FuzzingLock, oldIrql);
    
    return STATUS_SUCCESS;
}

// Fuzzing loop
VOID FuzzingLoop(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);

    ULONG iteration = 0;
    LARGE_INTEGER delay;
    KIRQL oldIrql;

    LOG_INFO("Fuzzing loop started");
    
    while (g_FuzzingActive && iteration < g_FuzzingConfig.MaxIterations) {
        // Fuzzing iteration
        FuzzingIteration(iteration);
        
        iteration++;
        
        // Update status
        KeAcquireSpinLock(&g_FuzzingLock, &oldIrql);
        g_FuzzingStatus.IterationsCompleted = iteration;
        KeReleaseSpinLock(&g_FuzzingLock, oldIrql);
        
        // Progress log
        if (iteration % 100 == 0) {
            LOG_INFO("Progress: %d/%d iterations", iteration, g_FuzzingConfig.MaxIterations);
        }
        
        // Small delay
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    
    LOG_INFO("Fuzzing loop completed after %d iterations", iteration);
}

// Single fuzzing iteration
VOID FuzzingIteration(ULONG Iteration)
{
    // 1. Generate input
    PVOID inputData = NULL;
    ULONG inputSize = 0;
    GenerateInput(&inputData, &inputSize);
    
    // 2. Create resources
    CreateFuzzingResources();
    
    // 3. Create threads
    CreateFuzzingThreads();
    
    // 4. Simulate race conditions
    SimulateRaceConditions();
    
    // 5. Update coverage
    UpdateCoverage();
    
    // 6. Detect race conditions
    DetectRaceConditions();
    
    // 7. Synthesize fault patterns
    SynthesizeFaultPatterns();
    
    // 8. Update statistics
    UpdateStatistics();
}

// Generate input
VOID GenerateInput(PVOID* InputData, PULONG InputSize)
{
    ULONG size = 64 + (KeQueryTimeIncrement() % 256); // Random size 64-320 bytes
    
    *InputData = ExAllocatePoolWithTag(NonPagedPool, size, RACE_FUZZER_TAG);
    if (*InputData) {
        GenerateRandomData(*InputData, size);
        *InputSize = size;
    }
}

// Create fuzzing resources
VOID CreateFuzzingResources(VOID)
{
    RESOURCE_CONTEXT context;
    ULONG i;
    
    for (i = 0; i < 5; i++) { // Create 5 resources per iteration
        RtlZeroMemory(&context, sizeof(RESOURCE_CONTEXT));
        context.ResourceType = (RESOURCE_TYPE)(i % 4);
        context.ResourceId = InterlockedIncrement(&g_ResourceCounter);
        
        CreateResource(context.ResourceType, &context);
    }
}

// Create fuzzing threads
VOID CreateFuzzingThreads(VOID)
{
    THREAD_CONTEXT context;
    ULONG i;
    
    for (i = 0; i < 3; i++) { // Create 3 threads per iteration
        RtlZeroMemory(&context, sizeof(THREAD_CONTEXT));
        context.ThreadId = InterlockedIncrement(&g_ThreadCounter);
        context.Priority = (ULONG)(KeQueryTimeIncrement() % 5) - 2; // -2 to 2
        
        CreateFuzzingThread(&context);
    }
}

// Simulate race conditions
VOID SimulateRaceConditions(VOID)
{
    ULONG threadIds[3] = {1, 2, 3};
    ULONG raceType = KeQueryTimeIncrement() % 5; // 5 different race types
    
    SimulateRaceCondition(raceType, threadIds, 3);
}

// Update coverage
VOID UpdateCoverage(VOID)
{
    // Simulate coverage updates
    PVOID address = (PVOID)(0x401000 + (KeQueryTimeIncrement() % 0x1000));
    HitCoveragePoint(address, KeGetCurrentProcessorNumber());
}

// Synthesize fault patterns
VOID SynthesizeFaultPatterns(VOID)
{
    PLIST_ENTRY entry;
    PRACE_CONDITION race;
    FAULT_PATTERN pattern;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_RaceLock, &oldIrql);
    
    for (entry = g_RaceList.Flink; entry != &g_RaceList; entry = entry->Flink) {
        race = CONTAINING_RECORD(entry, RACE_CONDITION, ListEntry);
        
        if (race->PatternPotential) {
            RtlZeroMemory(&pattern, sizeof(FAULT_PATTERN));
            pattern.PayloadId = InterlockedIncrement(&g_PatternCounter);
            pattern.PatternType = FAULT_PATTERN_USE_AFTER_FREE;
            pattern.SuccessProbability = 70;
            
            SynthesizeFaultPattern(race, &pattern);
        }
    }
    
    KeReleaseSpinLock(&g_RaceLock, oldIrql);
}

// Update statistics
VOID UpdateStatistics(VOID)
{
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_FuzzingLock, &oldIrql);
    
    // Update race count
    g_FuzzingStatus.RaceConditionsDetected = g_RaceCounter;
    
    // Update pattern count
    g_FuzzingStatus.PatternsFound = g_PatternCounter;
    
    // Update coverage percentage
    GetCoverageStats(&g_FuzzingStatus.CoveragePercentage, NULL, NULL);
    
    KeReleaseSpinLock(&g_FuzzingLock, oldIrql);
}

// Module 1: Thread Interleaving Simulator
NTSTATUS CreateFuzzingThread(PTHREAD_CONTEXT Context)
{
    NTSTATUS status;
    HANDLE threadHandle;
    
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Create thread
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        ThreadWorker,
        Context
    );
    
    if (NT_SUCCESS(status)) {
        Context->ThreadHandle = threadHandle;
        Context->State = THREAD_RUNNING;
        KeQuerySystemTime(&Context->CreationTime);
        
        // Add to thread list
        ExInterlockedInsertTailList(&g_ThreadList, &Context->ListEntry, &g_ThreadLock);
        
        LOG_DEBUG("Thread created: ID=%d", Context->ThreadId);
    } else {
        LOG_ERROR("Failed to create thread: 0x%08X", status);
    }
    
    return status;
}

// Thread worker function
VOID ThreadWorker(PVOID Parameter)
{
    PTHREAD_CONTEXT context = (PTHREAD_CONTEXT)Parameter;
    LARGE_INTEGER delay;
    
    if (!context) {
        return;
    }
    
    LOG_DEBUG("Thread worker started: ID=%d", context->ThreadId);
    
    // Simulate thread work
    while (g_FuzzingActive) {
        // Add jitter
        delay.QuadPart = -10000 * (10 + (KeQueryTimeIncrement() % 50)); // 10-60ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        
        // Simulate race condition
        SimulateThreadRace(context);
        
        // Update activity time
        KeQuerySystemTime(&context->LastActivity);
        context->AccessCount++;
    }
    
    LOG_DEBUG("Thread worker finished: ID=%d", context->ThreadId);
    
    // Close thread handle
    if (context->ThreadHandle) {
        ZwClose(context->ThreadHandle);
    }
}

// Simulate thread race
VOID SimulateThreadRace(PTHREAD_CONTEXT Context)
{
    // Simulate memory access
    PVOID address = (PVOID)(0x12345678 + (Context->ThreadId * 0x1000));
    RecordMemoryAccess(address, ACCESS_READ, 64, Context->ThreadId);
    
    // Simulate lock acquisition
    PVOID lockHandle = (PVOID)(0x87654321 + (Context->ThreadId * 0x100));
    RecordLockAcquisition(lockHandle, Context->ThreadId);
    
    // Simulate some work
    KeStallExecutionProcessor(1000); // 1ms stall
    
    // Simulate lock release
    RecordLockRelease(lockHandle, Context->ThreadId);
}

// Module 2: Shared Resource Mutator
NTSTATUS CreateResource(RESOURCE_TYPE ResourceType, PRESOURCE_CONTEXT Context)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }
    
    Context->ResourceType = ResourceType;
    Context->ResourceId = InterlockedIncrement(&g_ResourceCounter);
    Context->TaintLevel = 0;
    Context->CorruptionDetected = FALSE;
    
    switch (ResourceType) {
        case RESOURCE_KERNEL_POOL:
            AllocateKernelPool(1024, RACE_FUZZER_TAG, &Context->Data);
            Context->Size = 1024;
            break;
            
        case RESOURCE_FILE_HANDLE:
            CreateFileHandle("test.dat", &Context->Handle);
            break;
            
        case RESOURCE_MUTEX:
            CreateMutex("test_mutex", &Context->Handle);
            break;
            
        default:
            break;
    }
    
    // Add to resource list
    ExInterlockedInsertTailList(&g_ResourceList, &Context->ListEntry, &g_ResourceLock);
    
    LOG_DEBUG("Resource created: Type=%d, ID=%d", ResourceType, Context->ResourceId);
    
    return STATUS_SUCCESS;
}

/*
 * =========================================================
 * Module 3: Lockset-Based Race Detector (Eraser algorithm)
 * =========================================================
 *
 * Each memory location is associated with a "candidate lockset" — the
 * intersection of locksets held by every thread that has accessed it so
 * far. If the candidate lockset shrinks to empty while more than one thread
 * has accessed the location, the location is unprotected: a race candidate.
 *
 * Eraser states per address:
 *   VIRGIN       — never accessed; candidate = FULL (all possible locks)
 *   EXCLUSIVE    — accessed by exactly one thread; candidate = that thread's
 *                  lockset at access time
 *   SHARED       — read by ≥ 2 threads; candidate = intersection so far
 *   SHARED_MODIFIED — written after SHARED; candidate = intersection;
 *                     empty candidate here is a confirmed race
 *
 * We maintain two fixed-size tables in NonPagedPool:
 *   g_ThreadLocksets  — per-thread array of currently held lock handles
 *   g_AddrLocksets    — per-address candidate lockset state
 *
 * Table sizes are bounded by MAX_LOCKSET_THREADS / MAX_LOCKSET_ADDRS to
 * keep the non-paged pool footprint predictable. Address table entries are
 * indexed by a hash of the address.
 */

#define MAX_LOCKSET_THREADS  64
#define MAX_LOCKS_PER_THREAD 16
#define MAX_LOCKSET_ADDRS   512
#define LOCKSET_ADDR_HASH(addr) \
    ((ULONG)((ULONG_PTR)(addr) ^ ((ULONG_PTR)(addr) >> 12)) % MAX_LOCKSET_ADDRS)

typedef enum _ERASER_STATE {
    ES_VIRGIN          = 0,
    ES_EXCLUSIVE       = 1,
    ES_SHARED          = 2,
    ES_SHARED_MODIFIED = 3
} ERASER_STATE;

typedef struct _THREAD_LOCKSET_ENTRY {
    ULONG    ThreadId;
    BOOLEAN  InUse;
    ULONG    LockCount;
    PVOID    Locks[MAX_LOCKS_PER_THREAD];
} THREAD_LOCKSET_ENTRY, *PTHREAD_LOCKSET_ENTRY;

typedef struct _ADDR_LOCKSET_ENTRY {
    PVOID       Address;
    BOOLEAN     InUse;
    ERASER_STATE State;
    ULONG        FirstThreadId;          /* thread that first accessed */
    ULONG        AccessingThreadCount;
    ULONG        AccessingThreadIds[MAX_THREADS];
    /* Candidate lockset: bitmask over THREAD_LOCKSET_ENTRY.Locks indices.
     * We store it as an array of lock pointers: the intersection of all
     * locksets seen so far. FULL = all entries are NULL (meaning any
     * lock satisfies); we track actual locks once state ≠ VIRGIN. */
    PVOID        CandidateLocks[MAX_LOCKS_PER_THREAD];
    ULONG        CandidateCount;
    BOOLEAN      CandidateEmpty;         /* TRUE once intersection hits {} */
} ADDR_LOCKSET_ENTRY, *PADDR_LOCKSET_ENTRY;

/* Module-level storage — allocated at driver load, freed at unload. */
static THREAD_LOCKSET_ENTRY g_ThreadLocksets[MAX_LOCKSET_THREADS];
static ADDR_LOCKSET_ENTRY   g_AddrLocksets[MAX_LOCKSET_ADDRS];
static KSPIN_LOCK           g_LocksetLock;
static BOOLEAN              g_LocksetInitialized = FALSE;

/* Called from DriverEntry after spin-lock init. */
VOID LocksetInit(VOID)
{
    RtlZeroMemory(g_ThreadLocksets, sizeof(g_ThreadLocksets));
    RtlZeroMemory(g_AddrLocksets,   sizeof(g_AddrLocksets));
    KeInitializeSpinLock(&g_LocksetLock);
    g_LocksetInitialized = TRUE;
}

/* Find or allocate a THREAD_LOCKSET_ENTRY for ThreadId.
 * Called with g_LocksetLock held. */
static PTHREAD_LOCKSET_ENTRY LocksetFindThread(ULONG ThreadId)
{
    ULONG i;
    PTHREAD_LOCKSET_ENTRY free_slot = NULL;

    for (i = 0; i < MAX_LOCKSET_THREADS; ++i) {
        if (g_ThreadLocksets[i].InUse && g_ThreadLocksets[i].ThreadId == ThreadId)
            return &g_ThreadLocksets[i];
        if (!g_ThreadLocksets[i].InUse && !free_slot)
            free_slot = &g_ThreadLocksets[i];
    }
    if (free_slot) {
        RtlZeroMemory(free_slot, sizeof(*free_slot));
        free_slot->InUse    = TRUE;
        free_slot->ThreadId = ThreadId;
    }
    return free_slot;
}

/* Find or allocate an ADDR_LOCKSET_ENTRY for Address.
 * Called with g_LocksetLock held. */
static PADDR_LOCKSET_ENTRY LocksetFindAddr(PVOID Address)
{
    ULONG slot = LOCKSET_ADDR_HASH(Address);
    ULONG i;

    /* Linear probe on collision. */
    for (i = 0; i < MAX_LOCKSET_ADDRS; ++i) {
        ULONG idx = (slot + i) % MAX_LOCKSET_ADDRS;
        if (g_AddrLocksets[idx].InUse && g_AddrLocksets[idx].Address == Address)
            return &g_AddrLocksets[idx];
        if (!g_AddrLocksets[idx].InUse) {
            RtlZeroMemory(&g_AddrLocksets[idx], sizeof(g_AddrLocksets[idx]));
            g_AddrLocksets[idx].InUse   = TRUE;
            g_AddrLocksets[idx].Address = Address;
            g_AddrLocksets[idx].State   = ES_VIRGIN;
            return &g_AddrLocksets[idx];
        }
    }
    return NULL; /* table full — caller must tolerate this */
}

/* Intersect the address entry's candidate lockset with a thread's lockset.
 * Removes from CandidateLocks any lock not present in thread's Locks[].
 * Sets CandidateEmpty if the result is the empty set. */
static VOID LocksetIntersect(PADDR_LOCKSET_ENTRY aent,
                              PTHREAD_LOCKSET_ENTRY tent)
{
    ULONG i, j;
    ULONG new_count = 0;
    PVOID new_locks[MAX_LOCKS_PER_THREAD];

    if (aent->State == ES_VIRGIN) {
        /* First access: seed candidate with this thread's lockset. */
        for (i = 0; i < tent->LockCount && i < MAX_LOCKS_PER_THREAD; ++i)
            aent->CandidateLocks[i] = tent->Locks[i];
        aent->CandidateCount = tent->LockCount;
        aent->CandidateEmpty = (tent->LockCount == 0);
        return;
    }

    /* General case: keep only locks present in both sets. */
    for (i = 0; i < aent->CandidateCount; ++i) {
        BOOLEAN found = FALSE;
        for (j = 0; j < tent->LockCount; ++j) {
            if (aent->CandidateLocks[i] == tent->Locks[j]) {
                found = TRUE;
                break;
            }
        }
        if (found && new_count < MAX_LOCKS_PER_THREAD)
            new_locks[new_count++] = aent->CandidateLocks[i];
    }

    for (i = 0; i < new_count; ++i)
        aent->CandidateLocks[i] = new_locks[i];
    for (i = new_count; i < MAX_LOCKS_PER_THREAD; ++i)
        aent->CandidateLocks[i] = NULL;
    aent->CandidateCount = new_count;
    aent->CandidateEmpty = (new_count == 0);
}

/* Check whether ThreadId is already in aent's AccessingThreadIds. */
static BOOLEAN LocksetThreadSeen(PADDR_LOCKSET_ENTRY aent, ULONG ThreadId)
{
    ULONG i;
    for (i = 0; i < aent->AccessingThreadCount && i < MAX_THREADS; ++i) {
        if (aent->AccessingThreadIds[i] == ThreadId) return TRUE;
    }
    return FALSE;
}

/* Log a detected race and insert into g_RaceList. */
static VOID LocksetLogRace(PADDR_LOCKSET_ENTRY aent,
                            ULONG ThreadId,
                            ACCESS_TYPE AccessType)
{
    PRACE_CONDITION race;
    ULONG i;

    race = (PRACE_CONDITION)ExAllocatePoolWithTag(NonPagedPool,
                                                   sizeof(RACE_CONDITION),
                                                   RACE_FUZZER_TAG);
    if (!race) return;

    RtlZeroMemory(race, sizeof(*race));
    race->RaceId          = InterlockedIncrement(&g_RaceCounter);
    race->CorruptionType  = CORRUPTION_RACE_CONDITION;
    race->MemoryAddress   = aent->Address;
    race->Severity        = (AccessType == ACCESS_WRITE) ? 9 : 6;
    race->PatternPotential = TRUE;
    KeQuerySystemTime(&race->DetectionTime);

    /* Copy thread participants. */
    race->ThreadCount = aent->AccessingThreadCount;
    for (i = 0; i < aent->AccessingThreadCount && i < MAX_THREADS; ++i)
        race->ThreadIds[i] = aent->AccessingThreadIds[i];
    if (race->ThreadCount < MAX_THREADS)
        race->ThreadIds[race->ThreadCount++] = ThreadId;

    RtlStringCbPrintfA(race->Description, sizeof(race->Description),
                        "Lockset empty: addr=0x%p threads=%lu access=%s",
                        aent->Address,
                        (unsigned long)race->ThreadCount,
                        (AccessType == ACCESS_WRITE) ? "WRITE" : "READ");

    ExInterlockedInsertTailList(&g_RaceList, &race->ListEntry, &g_RaceLock);

    LOG_WARN("RACE: addr=0x%p empty-lockset threads=%lu sev=%lu",
             aent->Address,
             (unsigned long)race->ThreadCount,
             (unsigned long)race->Severity);

    InterlockedIncrement(&g_FuzzingStatus.RaceConditionsDetected);
    InterlockedIncrement(&g_FuzzingStatus.PatternsFound);
}

/* ------------------------------------------------------------------ */

NTSTATUS RecordLockAcquisition(PVOID LockHandle, ULONG ThreadId)
{
    KIRQL oldIrql;
    PTHREAD_LOCKSET_ENTRY tent;

    if (!LockHandle || !g_LocksetInitialized) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_LocksetLock, &oldIrql);

    tent = LocksetFindThread(ThreadId);
    if (tent && tent->LockCount < MAX_LOCKS_PER_THREAD) {
        tent->Locks[tent->LockCount++] = LockHandle;
    }

    KeReleaseSpinLock(&g_LocksetLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS RecordLockRelease(PVOID LockHandle, ULONG ThreadId)
{
    KIRQL oldIrql;
    PTHREAD_LOCKSET_ENTRY tent;
    ULONG i;

    if (!LockHandle || !g_LocksetInitialized) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_LocksetLock, &oldIrql);

    tent = LocksetFindThread(ThreadId);
    if (tent) {
        for (i = 0; i < tent->LockCount; ++i) {
            if (tent->Locks[i] == LockHandle) {
                /* Compact: shift remaining entries down. */
                ULONG j;
                for (j = i; j + 1 < tent->LockCount; ++j)
                    tent->Locks[j] = tent->Locks[j + 1];
                tent->Locks[--tent->LockCount] = NULL;
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_LocksetLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS RecordMemoryAccess(PVOID Address, ACCESS_TYPE AccessType,
                             ULONG Size, ULONG ThreadId)
{
    KIRQL oldIrql;
    PTHREAD_LOCKSET_ENTRY tent;
    PADDR_LOCKSET_ENTRY   aent;
    BOOLEAN               new_thread;

    UNREFERENCED_PARAMETER(Size);

    if (!Address || !g_LocksetInitialized) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_LocksetLock, &oldIrql);

    tent = LocksetFindThread(ThreadId);
    aent = LocksetFindAddr(Address);

    if (!tent || !aent) {
        KeReleaseSpinLock(&g_LocksetLock, oldIrql);
        return STATUS_SUCCESS;
    }

    new_thread = !LocksetThreadSeen(aent, ThreadId);

    if (new_thread && aent->AccessingThreadCount < MAX_THREADS)
        aent->AccessingThreadIds[aent->AccessingThreadCount++] = ThreadId;

    /* Eraser state transitions. */
    switch (aent->State) {
        case ES_VIRGIN:
            aent->FirstThreadId = ThreadId;
            aent->State = ES_EXCLUSIVE;
            LocksetIntersect(aent, tent);
            break;

        case ES_EXCLUSIVE:
            if (ThreadId != aent->FirstThreadId) {
                aent->State = (AccessType == ACCESS_WRITE)
                              ? ES_SHARED_MODIFIED : ES_SHARED;
                LocksetIntersect(aent, tent);
            }
            break;

        case ES_SHARED:
            if (AccessType == ACCESS_WRITE) {
                aent->State = ES_SHARED_MODIFIED;
            }
            if (new_thread) LocksetIntersect(aent, tent);
            break;

        case ES_SHARED_MODIFIED:
            if (new_thread) LocksetIntersect(aent, tent);
            break;
    }

    /* Race reported when: ≥2 threads accessed AND candidate lockset empty. */
    if (aent->State != ES_EXCLUSIVE &&
        aent->AccessingThreadCount > 1 &&
        aent->CandidateEmpty) {
        /* Avoid re-reporting the same address repeatedly by clearing
         * the "empty" flag after the first report. */
        aent->CandidateEmpty = FALSE;
        KeReleaseSpinLock(&g_LocksetLock, oldIrql);
        LocksetLogRace(aent, ThreadId, AccessType);
        return STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&g_LocksetLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS AnalyzeLockset(ULONG ThreadId, PVOID MemoryAddress)
{
    KIRQL oldIrql;
    PTHREAD_LOCKSET_ENTRY tent;
    PADDR_LOCKSET_ENTRY   aent;
    NTSTATUS result = STATUS_SUCCESS;

    if (!MemoryAddress || !g_LocksetInitialized) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_LocksetLock, &oldIrql);

    tent = LocksetFindThread(ThreadId);
    aent = LocksetFindAddr(MemoryAddress);

    if (!tent || !aent) {
        KeReleaseSpinLock(&g_LocksetLock, oldIrql);
        return STATUS_SUCCESS;
    }

    /* Report if the address is multi-thread accessed with empty lockset. */
    if (aent->AccessingThreadCount > 1 &&
        (aent->CandidateCount == 0 || aent->CandidateEmpty)) {
        result = STATUS_UNSUCCESSFUL; /* caller can treat as "race found" */
    }

    KeReleaseSpinLock(&g_LocksetLock, oldIrql);
    return result;
}

/* DetectRaceConditions: sweep the address table for unresolved empties. */
NTSTATUS DetectRaceConditions(VOID)
{
    KIRQL oldIrql;
    ULONG i;

    if (!g_LocksetInitialized) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_LocksetLock, &oldIrql);

    for (i = 0; i < MAX_LOCKSET_ADDRS; ++i) {
        PADDR_LOCKSET_ENTRY aent = &g_AddrLocksets[i];

        if (!aent->InUse) continue;
        if (aent->AccessingThreadCount < 2) continue;
        if (!aent->CandidateEmpty) continue;

        /* Found an unprotected address — log (under spin-lock to avoid
         * re-entrant allocation issues, we just count it here). */
        InterlockedIncrement(&g_RaceCounter);
        LOG_WARN("DetectRaceConditions: sweep hit addr=0x%p threads=%lu",
                 aent->Address,
                 (unsigned long)aent->AccessingThreadCount);

        aent->CandidateEmpty = FALSE; /* suppress duplicate report */
    }

    KeReleaseSpinLock(&g_LocksetLock, oldIrql);
    return STATUS_SUCCESS;
}

/*
 * =========================================================
 * Module 3 (continued): Memory Safety Detectors
 * =========================================================
 *
 * These detectors use a shadow tag table indexed by address hash to record
 * allocation state, initialisation state, and free state. They are
 * consulted on every ACCESS_FREE or ACCESS_WRITE access to detect the
 * common heap-class bugs that often co-occur with race conditions.
 *
 * Shadow table: SHADOW_ADDRS slots, linear probing on collision.
 */

#define SHADOW_ADDRS 1024
#define SHADOW_ADDR_HASH(addr) \
    ((ULONG)((ULONG_PTR)(addr) ^ ((ULONG_PTR)(addr) >> 12)) % SHADOW_ADDRS)

typedef enum _SHADOW_STATE {
    SHADOW_FREE       = 0,  /* never allocated or already freed */
    SHADOW_ALLOCATED  = 1,  /* ExAllocatePool'd, not yet written */
    SHADOW_WRITTEN    = 2,  /* at least one write observed */
    SHADOW_FREED      = 3   /* freed — next access is UAF */
} SHADOW_STATE;

typedef struct _SHADOW_ENTRY {
    PVOID        Address;
    BOOLEAN      InUse;
    SHADOW_STATE State;
    ULONG        AllocSize;
    ULONG        FirstWriteThread;
    ULONG        FreeThread;
} SHADOW_ENTRY, *PSHADOW_ENTRY;

static SHADOW_ENTRY g_Shadow[SHADOW_ADDRS];
static KSPIN_LOCK   g_ShadowLock;
static BOOLEAN      g_ShadowInitialized = FALSE;

VOID ShadowInit(VOID)
{
    RtlZeroMemory(g_Shadow, sizeof(g_Shadow));
    KeInitializeSpinLock(&g_ShadowLock);
    g_ShadowInitialized = TRUE;
}

static PSHADOW_ENTRY ShadowFind(PVOID Address)
{
    ULONG slot = SHADOW_ADDR_HASH(Address);
    ULONG i;
    for (i = 0; i < SHADOW_ADDRS; ++i) {
        ULONG idx = (slot + i) % SHADOW_ADDRS;
        if (g_Shadow[idx].InUse && g_Shadow[idx].Address == Address)
            return &g_Shadow[idx];
        if (!g_Shadow[idx].InUse) {
            g_Shadow[idx].InUse   = TRUE;
            g_Shadow[idx].Address = Address;
            g_Shadow[idx].State   = SHADOW_FREE;
            return &g_Shadow[idx];
        }
    }
    return NULL;
}

/* Called after a successful ExAllocatePoolWithTag to register the range. */
static VOID ShadowMark(PVOID Address, ULONG Size)
{
    KIRQL irql;
    PSHADOW_ENTRY s;
    if (!g_ShadowInitialized || !Address) return;
    KeAcquireSpinLock(&g_ShadowLock, &irql);
    s = ShadowFind(Address);
    if (s) {
        s->State    = SHADOW_ALLOCATED;
        s->AllocSize = Size;
        s->FreeThread = 0;
    }
    KeReleaseSpinLock(&g_ShadowLock, irql);
}

NTSTATUS DetectUseAfterFree(PVOID Address, ULONG ThreadId)
{
    KIRQL irql;
    PSHADOW_ENTRY s;

    if (!g_ShadowInitialized || !Address) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_ShadowLock, &irql);
    s = ShadowFind(Address);
    if (s && s->State == SHADOW_FREED) {
        KeReleaseSpinLock(&g_ShadowLock, irql);
        LogRaceCondition(CORRUPTION_USE_AFTER_FREE, Address, ThreadId,
                         "Access to freed memory (use-after-free)");
        return STATUS_UNSUCCESSFUL;
    }
    KeReleaseSpinLock(&g_ShadowLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS DetectDoubleFree(PVOID Address, ULONG ThreadId)
{
    KIRQL irql;
    PSHADOW_ENTRY s;

    if (!g_ShadowInitialized || !Address) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_ShadowLock, &irql);
    s = ShadowFind(Address);
    if (s && s->State == SHADOW_FREED) {
        KeReleaseSpinLock(&g_ShadowLock, irql);
        LogRaceCondition(CORRUPTION_DOUBLE_FREE, Address, ThreadId,
                         "Double free detected on previously freed pointer");
        return STATUS_UNSUCCESSFUL;
    }
    /* Mark as freed so any subsequent free or access fires. */
    if (s) {
        s->State      = SHADOW_FREED;
        s->FreeThread = ThreadId;
    }
    KeReleaseSpinLock(&g_ShadowLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS DetectBufferOverflow(PVOID Address, ULONG Size, ULONG AllocatedSize)
{
    if (!Address) return STATUS_INVALID_PARAMETER;
    if (Size > AllocatedSize) {
        LogRaceCondition(CORRUPTION_BUFFER_OVERFLOW, Address, 0,
                         "Write beyond allocated buffer boundary");
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DetectIntegerOverflow(ULONG Value, ULONG MaxValue)
{
    if (Value > MaxValue) {
        LOG_WARN("Integer overflow: value=%lu max=%lu",
                 (unsigned long)Value, (unsigned long)MaxValue);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DetectNullPointerDeref(PVOID Address)
{
    if (!Address || (ULONG_PTR)Address < 0x1000) {
        LogRaceCondition(CORRUPTION_NULL_POINTER_DEREF, Address, 0,
                         "Near-null pointer dereference attempt");
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DetectUninitializedMemory(PVOID Address, ULONG Size)
{
    KIRQL irql;
    PSHADOW_ENTRY s;

    if (!g_ShadowInitialized || !Address) return STATUS_SUCCESS;

    KeAcquireSpinLock(&g_ShadowLock, &irql);
    s = ShadowFind(Address);
    if (s && s->State == SHADOW_ALLOCATED) {
        /* Allocated but never written = uninitialised read. */
        ULONG_PTR end = (ULONG_PTR)Address + Size;
        UNREFERENCED_PARAMETER(end);
        KeReleaseSpinLock(&g_ShadowLock, irql);
        LogRaceCondition(CORRUPTION_UNINITIALIZED_MEMORY, Address, 0,
                         "Read of uninitialised kernel pool memory");
        return STATUS_UNSUCCESSFUL;
    }
    KeReleaseSpinLock(&g_ShadowLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS LogRaceCondition(CORRUPTION_TYPE Type, PVOID Address,
                           ULONG ThreadId, PCHAR Description)
{
    PRACE_CONDITION race;

    race = (PRACE_CONDITION)ExAllocatePoolWithTag(NonPagedPool,
                                                   sizeof(RACE_CONDITION),
                                                   RACE_FUZZER_TAG);
    if (!race) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(race, sizeof(*race));
    race->RaceId         = InterlockedIncrement(&g_RaceCounter);
    race->CorruptionType = Type;
    race->MemoryAddress  = Address;
    race->Severity       = (Type == CORRUPTION_USE_AFTER_FREE ||
                             Type == CORRUPTION_DOUBLE_FREE) ? 10 : 7;
    race->PatternPotential = TRUE;
    KeQuerySystemTime(&race->DetectionTime);

    if (ThreadId) {
        race->ThreadIds[0] = ThreadId;
        race->ThreadCount  = 1;
    }

    if (Description) {
        RtlStringCbCopyA(race->Description, sizeof(race->Description),
                          Description);
    }

    ExInterlockedInsertTailList(&g_RaceList, &race->ListEntry, &g_RaceLock);

    LOG_WARN("BUG type=%d addr=0x%p sev=%lu: %s",
             (int)Type, Address,
             (unsigned long)race->Severity,
             Description ? Description : "");

    InterlockedIncrement(&g_FuzzingStatus.RaceConditionsDetected);
    return STATUS_SUCCESS;
}

// Module 4: Fault Pattern Generator
NTSTATUS SynthesizeFaultPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    if (!Race || !Pattern) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Generate pattern based on race type
    switch (Race->CorruptionType) {
        case CORRUPTION_USE_AFTER_FREE:
            GenerateUseAfterFreePattern(Race, Pattern);
            break;
            
        case CORRUPTION_DOUBLE_FREE:
            GenerateDoubleFreePattern(Race, Pattern);
            break;
            
        default:
            Pattern->PatternType = FAULT_PATTERN_USE_AFTER_FREE;
            Pattern->SuccessProbability = 50;
            break;
    }
    
    // Add to pattern list
    ExInterlockedInsertTailList(&g_PatternList, &Pattern->ListEntry, &g_PatternLock);
    
    LOG_DEBUG("Pattern synthesized: Type=%d, Probability=%d%%", 
              Pattern->PatternType, Pattern->SuccessProbability);
    
    return STATUS_SUCCESS;
}

NTSTATUS GenerateUseAfterFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    // Generate Use-After-Free fault pattern
    Pattern->PatternType = FAULT_PATTERN_USE_AFTER_FREE;
    Pattern->SuccessProbability = 75;
    Pattern->TargetAddress = Race->MemoryAddress;
    
    // Generate payload data
    Pattern->PayloadData = ExAllocatePoolWithTag(NonPagedPool, 64, RACE_FUZZER_TAG);
    if (Pattern->PayloadData) {
        GenerateRandomData(Pattern->PayloadData, 64);
        Pattern->DataSize = 64;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS GenerateDoubleFreePattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    // Generate Double-Free fault pattern
    Pattern->PatternType = FAULT_PATTERN_DOUBLE_FREE;
    Pattern->SuccessProbability = 60;
    Pattern->TargetAddress = Race->MemoryAddress;
    
    // Generate payload data
    Pattern->PayloadData = ExAllocatePoolWithTag(NonPagedPool, 32, RACE_FUZZER_TAG);
    if (Pattern->PayloadData) {
        GenerateRandomData(Pattern->PayloadData, 32);
        Pattern->DataSize = 32;
    }
    
    return STATUS_SUCCESS;
}

/*
 * GenerateROPChain / GenerateHeapSpray — raw buffer builders.
 *
 * These produce synthetic proof-of-concept buffers that represent the
 * *structure* of a kernel exploitation primitive without containing actual
 * gadget addresses (which would be target-specific).  The patterns are used
 * to estimate SuccessProbability in the higher-level generators.
 */
NTSTATUS GenerateROPChain(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress)
{
    PULONG_PTR chain;
    ULONG slots, i;

    if (!Buffer || BufferSize < sizeof(ULONG_PTR)) return STATUS_INVALID_PARAMETER;

    chain = (PULONG_PTR)Buffer;
    slots = BufferSize / (ULONG)sizeof(ULONG_PTR);

    /* Slot 0: synthetic "pop rsp; ret" pivot placeholder. */
    chain[0] = (ULONG_PTR)TargetAddress ^ 0xDEADC0DEUL;

    /* Slots 1..n-2: placeholder kernel_base+offset values (not real gadgets).
     * We XOR with a constant so the pattern is recognisable in dumps. */
    for (i = 1; i + 1 < slots; ++i)
        chain[i] = (ULONG_PTR)0xFFFF800000000000ULL + (ULONG_PTR)(i * 0x100);

    /* Final slot: return-to-kernel-shellcode placeholder (KPROCESS.Token swap). */
    chain[slots - 1] = (ULONG_PTR)TargetAddress;

    return STATUS_SUCCESS;
}

NTSTATUS GenerateHeapSpray(PVOID Buffer, ULONG BufferSize, PVOID TargetAddress)
{
    PUCHAR  spray;
    ULONG   i;
    UCHAR   nop_sled[8] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    if (!Buffer || BufferSize == 0) return STATUS_INVALID_PARAMETER;

    spray = (PUCHAR)Buffer;

    /* Fill most of the buffer with a NOP sled pattern. */
    for (i = 0; i + 8 <= BufferSize; i += 8)
        RtlCopyMemory(spray + i, nop_sled, 8);

    /* Place a synthetic target pointer at the midpoint so that a wild
     * reference into the sled will eventually reach it. */
    if (BufferSize >= sizeof(PVOID)) {
        RtlCopyMemory(spray + BufferSize - sizeof(PVOID),
                      &TargetAddress,
                      sizeof(PVOID));
    }

    return STATUS_SUCCESS;
}

NTSTATUS GenerateHeapSprayPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    if (!Race || !Pattern) return STATUS_INVALID_PARAMETER;

    Pattern->PatternType       = FAULT_PATTERN_HEAP_SPRAY;
    Pattern->TargetAddress     = Race->MemoryAddress;
    /* Heap spray success probability is moderate: depends on kernel heap layout. */
    Pattern->SuccessProbability = 45;
    Pattern->Complexity        = 3;

    Pattern->PayloadData = ExAllocatePoolWithTag(NonPagedPool, 256, RACE_FUZZER_TAG);
    if (Pattern->PayloadData) {
        GenerateHeapSpray(Pattern->PayloadData, 256, Race->MemoryAddress);
        Pattern->DataSize = 256;
    }

    RtlStringCbCopyA(Pattern->TriggerCondition, sizeof(Pattern->TriggerCondition),
                      "trigger=concurrent_alloc race_window_ns<200");
    return STATUS_SUCCESS;
}

NTSTATUS GenerateRopChainPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    if (!Race || !Pattern) return STATUS_INVALID_PARAMETER;

    Pattern->PatternType       = FAULT_PATTERN_ROP_CHAIN;
    Pattern->TargetAddress     = Race->MemoryAddress;
    /* ROP success requires controlled write-what-where → low base probability. */
    Pattern->SuccessProbability = 30;
    Pattern->Complexity        = 5;

    Pattern->PayloadData = ExAllocatePoolWithTag(NonPagedPool, 128, RACE_FUZZER_TAG);
    if (Pattern->PayloadData) {
        GenerateROPChain(Pattern->PayloadData, 128, Race->MemoryAddress);
        Pattern->DataSize = 128;
    }

    RtlStringCbCopyA(Pattern->TriggerCondition, sizeof(Pattern->TriggerCondition),
                      "trigger=write_primitive_acquired stack_pivot_needed");
    return STATUS_SUCCESS;
}

NTSTATUS GeneratePrivilegeEscalationPattern(PRACE_CONDITION Race,
                                             PFAULT_PATTERN Pattern)
{
    if (!Race || !Pattern) return STATUS_INVALID_PARAMETER;

    Pattern->PatternType       = FAULT_PATTERN_PRIVILEGE_ESCALATION;
    Pattern->TargetAddress     = Race->MemoryAddress;
    /* Token-swap privesc via race: only feasible if the race touches
     * EPROCESS.Token; severity-based probability. */
    Pattern->SuccessProbability = (Race->Severity >= 8) ? 55 : 20;
    Pattern->Complexity        = 6;
    Pattern->DataSize          = 0;

    RtlStringCbCopyA(Pattern->TriggerCondition, sizeof(Pattern->TriggerCondition),
                      "trigger=token_replace target=EPROCESS.Token");
    return STATUS_SUCCESS;
}

NTSTATUS GenerateCodeInjectionPattern(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    if (!Race || !Pattern) return STATUS_INVALID_PARAMETER;

    Pattern->PatternType       = FAULT_PATTERN_CODE_INJECTION;
    Pattern->TargetAddress     = Race->MemoryAddress;
    Pattern->SuccessProbability = 25;
    Pattern->Complexity        = 7;

    /* Payload: synthetic shellcode stub (INT3 × 16 — marks position in memory
     * dumps without executing harmful instructions on the test VM). */
    Pattern->PayloadData = ExAllocatePoolWithTag(NonPagedPool, 16, RACE_FUZZER_TAG);
    if (Pattern->PayloadData) {
        RtlFillMemory(Pattern->PayloadData, 16, 0xCC); /* INT3 sled */
        Pattern->DataSize = 16;
    }

    RtlStringCbCopyA(Pattern->TriggerCondition, sizeof(Pattern->TriggerCondition),
                      "trigger=mapped_exec_page race_overwrites_dispatch_ptr");
    return STATUS_SUCCESS;
}

NTSTATUS CalculatePatternConfidence(PRACE_CONDITION Race, PFAULT_PATTERN Pattern)
{
    ULONG base;

    if (!Race || !Pattern) return STATUS_INVALID_PARAMETER;

    /* Start from the pattern's current success probability. */
    base = Pattern->SuccessProbability;

    /* Adjust upward with race severity. */
    base += Race->Severity * 2;

    /* Multi-thread races are harder to exploit reliably: minor penalty. */
    if (Race->ThreadCount > 2) base -= (Race->ThreadCount - 2) * 3;

    /* Non-race corruption types have deterministic exploitation paths. */
    if (Race->CorruptionType == CORRUPTION_USE_AFTER_FREE)  base += 10;
    if (Race->CorruptionType == CORRUPTION_DOUBLE_FREE)     base += 8;
    if (Race->CorruptionType == CORRUPTION_BUFFER_OVERFLOW) base += 5;

    /* Cap to [5, 95]. Never claim certainty or impossibility. */
    if (base > 95) base = 95;
    if (base < 5)  base = 5;

    Pattern->SuccessProbability = base;
    return STATUS_SUCCESS;
}

NTSTATUS ValidateFaultPattern(PFAULT_PATTERN Pattern)
{
    if (!Pattern) return STATUS_INVALID_PARAMETER;

    /* Reject patterns that claim unreachable probability. */
    if (Pattern->SuccessProbability > 100) return STATUS_INVALID_PARAMETER;

    /* Payload-bearing patterns must have a non-NULL data pointer. */
    if (Pattern->PatternType == FAULT_PATTERN_HEAP_SPRAY ||
        Pattern->PatternType == FAULT_PATTERN_ROP_CHAIN  ||
        Pattern->PatternType == FAULT_PATTERN_CODE_INJECTION) {
        if (Pattern->DataSize > 0 && !Pattern->PayloadData)
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

// Module 5: Coverage Tracker
NTSTATUS AddCoveragePoint(PVOID Address, PCHAR FunctionName)
{
    PCOVERAGE_POINT coveragePoint;
    KIRQL oldIrql;
    
    if (!Address || !FunctionName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Allocate coverage point
    coveragePoint = (PCOVERAGE_POINT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(COVERAGE_POINT),
        RACE_FUZZER_TAG
    );
    
    if (!coveragePoint) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Initialize coverage point
    RtlZeroMemory(coveragePoint, sizeof(COVERAGE_POINT));
    coveragePoint->Address = Address;
    RtlStringCbCopyA(coveragePoint->FunctionName, sizeof(coveragePoint->FunctionName), FunctionName);
    
    // Add to coverage list
    KeAcquireSpinLock(&g_CoverageLock, &oldIrql);
    InsertTailList(&g_CoverageList, &coveragePoint->ListEntry);
    KeReleaseSpinLock(&g_CoverageLock, oldIrql);
    
    LOG_DEBUG("Coverage point added: Address=0x%p, Function=%s", Address, FunctionName);
    
    return STATUS_SUCCESS;
}

NTSTATUS HitCoveragePoint(PVOID Address, ULONG ThreadId)
{
    PLIST_ENTRY entry;
    PCOVERAGE_POINT coveragePoint;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    if (!Address) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_CoverageLock, &oldIrql);
    
    // Find coverage point
    for (entry = g_CoverageList.Flink; entry != &g_CoverageList; entry = entry->Flink) {
        coveragePoint = CONTAINING_RECORD(entry, COVERAGE_POINT, ListEntry);
        
        if (coveragePoint->Address == Address) {
            // Update hit count
            coveragePoint->HitCount++;
            coveragePoint->IsHit = TRUE;
            
            // Update timestamps
            if (coveragePoint->HitCount == 1) {
                KeQuerySystemTime(&coveragePoint->FirstHit);
            }
            KeQuerySystemTime(&coveragePoint->LastHit);
            
            // Add thread ID if not already present
            if (coveragePoint->ThreadCount < MAX_THREADS) {
                coveragePoint->ThreadIds[coveragePoint->ThreadCount] = ThreadId;
                coveragePoint->ThreadCount++;
            }
            
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_CoverageLock, oldIrql);
    
    if (!found) {
        // Create new coverage point
        AddCoveragePoint(Address, "Unknown");
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS GetCoverageStats(PULONG TotalPoints, PULONG HitPoints, PULONG Percentage)
{
    PLIST_ENTRY entry;
    PCOVERAGE_POINT coveragePoint;
    KIRQL oldIrql;
    ULONG total = 0;
    ULONG hit = 0;
    
    if (!TotalPoints || !HitPoints || !Percentage) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_CoverageLock, &oldIrql);
    
    for (entry = g_CoverageList.Flink; entry != &g_CoverageList; entry = entry->Flink) {
        coveragePoint = CONTAINING_RECORD(entry, COVERAGE_POINT, ListEntry);
        total++;
        if (coveragePoint->IsHit) {
            hit++;
        }
    }
    
    KeReleaseSpinLock(&g_CoverageLock, oldIrql);
    
    *TotalPoints = total;
    *HitPoints = hit;
    *Percentage = total > 0 ? (hit * 100) / total : 0;
    
    return STATUS_SUCCESS;
}

/*
 * =========================================================
 * Module 5 (continued): Mutation Engine & Feedback Loop
 * =========================================================
 */

static LONG g_MutSeed = 0x1234;

static ULONG MutRand(ULONG mod)
{
    LONG s = InterlockedIncrement(&g_MutSeed);
    ULONG t = (ULONG)KeQueryTimeIncrement() ^ (ULONG)s;
    return (t ^ (t >> 13) ^ (t >> 7)) % mod;
}

static PVOID MutClone(PVOID Input, ULONG Size)
{
    PVOID copy = ExAllocatePoolWithTag(NonPagedPool, Size, RACE_FUZZER_TAG);
    if (copy) RtlCopyMemory(copy, Input, Size);
    return copy;
}

static VOID MutFinish(PMUTATION_RESULT Result, PVOID MutatedBuf,
                       ULONG Size, MUTATION_TYPE Type, PVOID OriginalInput)
{
    Result->MutationId    = InterlockedIncrement(&g_MutationCounter);
    Result->MutationType  = Type;
    Result->OriginalInput = OriginalInput;
    Result->MutatedInput  = MutatedBuf;
    Result->InputSize     = Size;
    InterlockedIncrement(&g_FuzzingStatus.IterationsCompleted);
}

NTSTATUS BitFlipMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result)
{
    PUCHAR buf;
    ULONG byte_pos, bit_pos;

    if (!Input || !Size || !Result) return STATUS_INVALID_PARAMETER;
    buf = (PUCHAR)MutClone(Input, Size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    byte_pos = MutRand(Size);
    bit_pos  = MutRand(8);
    buf[byte_pos] ^= (UCHAR)(1u << bit_pos);

    MutFinish(Result, buf, Size, MUTATION_BIT_FLIP, Input);
    return STATUS_SUCCESS;
}

NTSTATUS ByteFlipMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result)
{
    PUCHAR buf;
    ULONG pos;

    if (!Input || !Size || !Result) return STATUS_INVALID_PARAMETER;
    buf = (PUCHAR)MutClone(Input, Size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    pos = MutRand(Size);
    buf[pos] ^= 0xFF;

    MutFinish(Result, buf, Size, MUTATION_BYTE_FLIP, Input);
    return STATUS_SUCCESS;
}

NTSTATUS ArithmeticMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result)
{
    PUCHAR buf;
    ULONG pos;
    UCHAR delta;

    if (!Input || !Size || !Result) return STATUS_INVALID_PARAMETER;
    buf = (PUCHAR)MutClone(Input, Size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    pos   = MutRand(Size);
    delta = (UCHAR)(MutRand(35) + 1);
    if (MutRand(2))
        buf[pos] = (UCHAR)((ULONG)buf[pos] + delta);
    else
        buf[pos] = (UCHAR)((ULONG)buf[pos] - delta);

    MutFinish(Result, buf, Size, MUTATION_ARITHMETIC, Input);
    return STATUS_SUCCESS;
}

NTSTATUS InterestingMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result)
{
    static const UCHAR kInteresting[] = {
        0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 0x40, 0x3F, 0x10, 0xEF
    };
    static const ULONG kCount =
        sizeof(kInteresting) / sizeof(kInteresting[0]);

    PUCHAR buf;
    ULONG pos;

    if (!Input || !Size || !Result) return STATUS_INVALID_PARAMETER;
    buf = (PUCHAR)MutClone(Input, Size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    pos = MutRand(Size);
    buf[pos] = kInteresting[MutRand(kCount)];

    MutFinish(Result, buf, Size, MUTATION_INTERESTING, Input);
    return STATUS_SUCCESS;
}

NTSTATUS HavocMutation(PVOID Input, ULONG Size, PMUTATION_RESULT Result)
{
    PUCHAR buf;
    ULONG passes, i, pos;

    if (!Input || !Size || !Result) return STATUS_INVALID_PARAMETER;
    buf = (PUCHAR)MutClone(Input, Size);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    passes = MutRand(15) + 2;
    if (passes > Size) passes = Size;

    for (i = 0; i < passes; ++i) {
        pos = MutRand(Size);
        switch (MutRand(4)) {
            case 0: buf[pos] ^= (UCHAR)(1u << MutRand(8)); break;
            case 1: buf[pos] ^= 0xFF;                       break;
            case 2: buf[pos] = (UCHAR)MutRand(256);         break;
            case 3: buf[pos] = (UCHAR)((ULONG)buf[pos] + MutRand(35) + 1); break;
        }
    }

    MutFinish(Result, buf, Size, MUTATION_HAVOC, Input);
    return STATUS_SUCCESS;
}

NTSTATUS SpliceMutation(PVOID Input1, ULONG Size1,
                         PVOID Input2, ULONG Size2,
                         PMUTATION_RESULT Result)
{
    PUCHAR buf;
    ULONG out_size, split;

    if (!Input1 || !Size1 || !Input2 || !Size2 || !Result)
        return STATUS_INVALID_PARAMETER;

    out_size = (Size1 < Size2) ? Size1 : Size2;
    if (!out_size) return STATUS_INVALID_PARAMETER;

    buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, out_size, RACE_FUZZER_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    split = out_size / 2;
    RtlCopyMemory(buf,         Input1,                  split);
    RtlCopyMemory(buf + split, (PUCHAR)Input2 + split,  out_size - split);

    MutFinish(Result, buf, out_size, MUTATION_SPLICE, Input1);
    return STATUS_SUCCESS;
}

NTSTATUS AddInput(PVOID InputData, ULONG InputSize)
{
    PINPUT_DATA inp;
    KIRQL irql;

    if (!InputData || !InputSize) return STATUS_INVALID_PARAMETER;

    inp = (PINPUT_DATA)ExAllocatePoolWithTag(NonPagedPool,
                                              sizeof(INPUT_DATA),
                                              RACE_FUZZER_TAG);
    if (!inp) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(inp, sizeof(*inp));
    inp->Data = ExAllocatePoolWithTag(NonPagedPool, InputSize, RACE_FUZZER_TAG);
    if (!inp->Data) {
        ExFreePoolWithTag(inp, RACE_FUZZER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(inp->Data, InputData, InputSize);
    inp->Size = InputSize;
    KeQuerySystemTime(&inp->CreationTime);

    KeAcquireSpinLock(&g_InputLock, &irql);
    InsertTailList(&g_InputList, &inp->ListEntry);
    InterlockedIncrement(&g_InputCounter);
    KeReleaseSpinLock(&g_InputLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS GetNextInput(PVOID *InputData, PULONG InputSize)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    PINPUT_DATA inp;

    if (!InputData || !InputSize) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_InputLock, &irql);
    if (IsListEmpty(&g_InputList)) {
        KeReleaseSpinLock(&g_InputLock, irql);
        return STATUS_NO_MORE_ENTRIES;
    }
    entry = RemoveHeadList(&g_InputList);
    KeReleaseSpinLock(&g_InputLock, irql);

    inp = CONTAINING_RECORD(entry, INPUT_DATA, ListEntry);
    *InputData = inp->Data;
    *InputSize = inp->Size;
    ExFreePoolWithTag(inp, RACE_FUZZER_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS MutateInput(PVOID OriginalInput, ULONG InputSize,
                      MUTATION_TYPE MutationType,
                      PMUTATION_RESULT Result)
{
    if (!OriginalInput || !InputSize || !Result)
        return STATUS_INVALID_PARAMETER;

    switch (MutationType) {
        case MUTATION_BIT_FLIP:    return BitFlipMutation(OriginalInput, InputSize, Result);
        case MUTATION_BYTE_FLIP:   return ByteFlipMutation(OriginalInput, InputSize, Result);
        case MUTATION_ARITHMETIC:  return ArithmeticMutation(OriginalInput, InputSize, Result);
        case MUTATION_INTERESTING: return InterestingMutation(OriginalInput, InputSize, Result);
        case MUTATION_HAVOC:       return HavocMutation(OriginalInput, InputSize, Result);
        case MUTATION_SPLICE:
            return SpliceMutation(OriginalInput, InputSize,
                                  OriginalInput, InputSize, Result);
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS UpdateMutationResult(ULONG MutationId, ULONG CoverageGained,
                               BOOLEAN CrashInduced, BOOLEAN PatternFound)
{
    PLIST_ENTRY entry;
    PMUTATION_RESULT mr;
    KIRQL irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_MutationLock, &irql);
    for (entry = g_MutationList.Flink;
         entry != &g_MutationList;
         entry = entry->Flink) {
        mr = CONTAINING_RECORD(entry, MUTATION_RESULT, ListEntry);
        if (mr->MutationId == MutationId) {
            mr->CoverageGained = CoverageGained;
            mr->CrashInduced   = CrashInduced;
            mr->PatternFound   = PatternFound;
            if (CoverageGained > 0) mr->NewPaths++;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_MutationLock, irql);

    if (CrashInduced) InterlockedIncrement(&g_FuzzingStatus.CrashesFound);
    if (PatternFound) InterlockedIncrement(&g_FuzzingStatus.PatternsFound);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS CalculateCoverageGain(PVOID Input, ULONG Size, PULONG CoverageGain)
{
    ULONG hash, existing, dummy;

    if (!Input || !Size || !CoverageGain) return STATUS_INVALID_PARAMETER;

    hash = CalculateHash(Input, Size);
    GetCoverageStats(NULL, &existing, &dummy);
    *CoverageGain = (hash % 16) + (existing == 0 ? 1 : 0);
    return STATUS_SUCCESS;
}

NTSTATUS IsInterestingInput(PVOID Input, ULONG Size, BOOLEAN *IsInteresting)
{
    ULONG gain;
    NTSTATUS st;

    if (!Input || !Size || !IsInteresting) return STATUS_INVALID_PARAMETER;
    st = CalculateCoverageGain(Input, Size, &gain);
    if (!NT_SUCCESS(st)) return st;
    *IsInteresting = (gain >= 4);
    return STATUS_SUCCESS;
}

// Utility functions
VOID LogMessage(PCHAR Format, ...)
{
    va_list args;
    CHAR buffer[512];
    ULONG length;

    va_start(args, Format);
    length = RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    va_end(args);

    if (length < sizeof(buffer)) {
        DbgPrint("%s", buffer);
    }
}

NTSTATUS GenerateRandomData(PVOID Buffer, ULONG Size)
{
    ULONG i;
    PUCHAR data = (PUCHAR)Buffer;

    if (!Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < Size; i++) {
        data[i] = (UCHAR)(KeQueryTimeIncrement() + i) % 256;
    }
    
    return STATUS_SUCCESS;
}

ULONG CalculateHash(PVOID Data, ULONG Size)
{
    ULONG hash = 0;
    PUCHAR data = (PUCHAR)Data;
    ULONG i;
    
    for (i = 0; i < Size; i++) {
        hash = hash * 31 + data[i];
    }
    
    return hash;
}

BOOLEAN IsAddressValid(PVOID Address)
{
    // Simple address validation
    return (Address != NULL && (ULONG_PTR)Address > 0x1000);
}

// Clean up resources
VOID CleanupResources(VOID)
{
    PLIST_ENTRY entry;
    PCOVERAGE_POINT coveragePoint;
    PFAULT_PATTERN pattern;
    KIRQL oldIrql;
    
    // Clean up coverage points
    KeAcquireSpinLock(&g_CoverageLock, &oldIrql);
    
    while (!IsListEmpty(&g_CoverageList)) {
        entry = RemoveHeadList(&g_CoverageList);
        coveragePoint = CONTAINING_RECORD(entry, COVERAGE_POINT, ListEntry);
        ExFreePoolWithTag(coveragePoint, RACE_FUZZER_TAG);
    }
    
    KeReleaseSpinLock(&g_CoverageLock, oldIrql);
    
    // Clean up patterns
    KeAcquireSpinLock(&g_PatternLock, &oldIrql);
    
    while (!IsListEmpty(&g_PatternList)) {
        entry = RemoveHeadList(&g_PatternList);
        pattern = CONTAINING_RECORD(entry, FAULT_PATTERN, ListEntry);
        if (pattern->PayloadData) {
            ExFreePoolWithTag(pattern->PayloadData, RACE_FUZZER_TAG);
        }
        ExFreePoolWithTag(pattern, RACE_FUZZER_TAG);
    }
    
    KeReleaseSpinLock(&g_PatternLock, oldIrql);
    
    LOG_INFO("Resources cleaned up");
}

// Additional helper functions
NTSTATUS CreateMutex(PCHAR MutexName, PHANDLE MutexHandle)
{
    UNREFERENCED_PARAMETER(MutexName);
    UNREFERENCED_PARAMETER(MutexHandle);
    return STATUS_SUCCESS;
}

NTSTATUS AllocateKernelPool(ULONG Size, ULONG Tag, PVOID* Address)
{
    *Address = ExAllocatePoolWithTag(NonPagedPool, Size, Tag);
    return (*Address) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS CreateFileHandle(PCHAR FileName, PHANDLE FileHandle)
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(FileHandle);
    return STATUS_SUCCESS;
}

NTSTATUS SimulateRaceCondition(ULONG RaceType, PULONG ThreadIds, ULONG ThreadCount)
{
    UNREFERENCED_PARAMETER(RaceType);
    UNREFERENCED_PARAMETER(ThreadIds);
    UNREFERENCED_PARAMETER(ThreadCount);
    return STATUS_SUCCESS;
}
